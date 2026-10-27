package operation

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/getkin/kin-openapi/openapi3"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func GenerateOperationID(method string, path string) string {
	idSource := strings.ToLower(method)
	pathParts := strings.Split(path, "/")
	newPathParts := []string{}
	caser := cases.Title(language.English)
	for _, part := range pathParts {
		if part != "" {
			newPathParts = append(newPathParts, caser.String(part))
		}
	}
	if len(newPathParts) == 0 {
		return idSource + "Root"
	}

	idSource += strings.Join(newPathParts, "")
	re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	return re.ReplaceAllString(idSource, "")
}

type Operation struct {
	*request.Client `json:"-" yaml:"-"`

	OpenAPIDocPath *string `json:"-" yaml:"-"`
	ID             string  `json:"id" yaml:"id"`

	Method          string                 `json:"method" yaml:"method"`
	URL             url.URL                `json:"url" yaml:"url"`
	Body            []byte                 `json:"body,omitempty" yaml:"body,omitempty"`
	Cookies         []*http.Cookie         `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Header          http.Header            `json:"header,omitempty" yaml:"header,omitempty"`
	SecuritySchemes []*auth.SecurityScheme `json:"securitySchemes" yaml:"securitySchemes"`
}

func getBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	if bodyBuffer, ok := body.(*bytes.Buffer); ok {
		if bodyBuffer == nil {
			return nil, nil
		}
		return bodyBuffer.Bytes(), nil
	}

	return io.ReadAll(body)
}

func NewOperation(method string, operationUrl string, body io.Reader, client *request.Client) (*Operation, error) {
	operationClient := client
	if operationClient == nil {
		operationClient = request.GetDefaultClient()
	}

	parsedUrl, err := url.Parse(operationUrl)
	if err != nil {
		return nil, err
	}

	bodyBuffer, err := getBody(body)
	if err != nil {
		return nil, err
	}

	return &Operation{
		Client: operationClient,

		Method:          method,
		URL:             *parsedUrl,
		Body:            bodyBuffer,
		Cookies:         []*http.Cookie{},
		Header:          http.Header{},
		SecuritySchemes: []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()},
	}, nil
}

func MustNewOperation(method string, operationUrl string, body *bytes.Buffer, client *request.Client) *Operation {
	operation, err := NewOperation(method, operationUrl, body, client)
	if err != nil {
		panic(err)
	}
	return operation
}

func (operation *Operation) IsReachable() error {
	host := operation.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		switch operation.URL.Scheme {
		case "http":
			host += ":80"
		case "https":
			host += ":443"
		default:
			return fmt.Errorf("unsupported scheme: %s", operation.URL.Scheme)
		}
	}

	if operation.URL.Scheme == "https" {
		tlsConfig := operation.Client.Transport.(*http.Transport).TLSClientConfig
		if tlsConfig == nil || !tlsConfig.InsecureSkipVerify {
			tlsConn, err := tls.Dial("tcp", host, tlsConfig)
			if err != nil {
				return err
			}
			defer tlsConn.Close()
		}
	}

	dialConn, err := net.DialTimeout("tcp", host, operation.Timeout)
	if err != nil {
		return err
	}
	defer dialConn.Close()

	return nil
}

// NewOperationFromHTTPRequest builds an Operation from a plain *http.Request
// (e.g. one built via probe.NewRequest), reading its body into memory so
// the Operation can be replayed via NewHTTPRequest.
func NewOperationFromHTTPRequest(r *http.Request) (*Operation, error) {
	body, err := getBody(r.Body)
	if err != nil {
		return nil, err
	}

	return &Operation{
		ID:      r.URL.String(),
		Method:  r.Method,
		URL:     *r.URL,
		Header:  r.Header,
		Cookies: r.Cookies(),
		Body:    body,

		SecuritySchemes: []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()},
	}, nil
}

func (operation *Operation) WithOpenapiOperation(docPath string, openapiOperation *openapi3.Operation) *Operation {
	if openapiOperation.OperationID != "" {
		operation.SetID(openapiOperation.OperationID)
	} else {
		operation.SetID(GenerateOperationID(operation.Method, docPath))
	}
	operation.OpenAPIDocPath = &docPath

	return operation
}

func (operation *Operation) WithHeader(header http.Header) *Operation {
	operation.Header = header
	return operation
}

func (operation *Operation) WithCookies(cookies []*http.Cookie) *Operation {
	operation.Cookies = cookies
	return operation
}

// withHeaderValues sets every value of a header, replacing existing ones.
func withHeaderValues(name string, values []string) probe.RequestMutator {
	return func(req *http.Request) error {
		req.Header.Del(name)
		for _, v := range values {
			req.Header.Add(name, v)
		}
		return nil
	}
}

// NewHTTPRequest builds a plain *http.Request for this operation via
// probe.NewRequest. It applies, in order: the client's User-Agent, headers
// and cookies (e.g. -A, -H and -b flags), the operation's own headers and
// cookies, then any extra mutators (e.g. auth.RequestMutators for a security
// scheme). Later values override earlier ones.
func (operation *Operation) NewHTTPRequest(ctx context.Context, mutators ...probe.RequestMutator) (*http.Request, error) {
	client := operation.requestClient()

	all := make([]probe.RequestMutator, 0, 1+len(client.Header)+len(client.Cookies)+len(operation.Header)+len(operation.Cookies)+len(mutators))
	all = append(all, probe.WithHeader("User-Agent", client.GetUserAgent()))
	for _, header := range []http.Header{client.Header, operation.Header} {
		for k, v := range header {
			if len(v) == 0 {
				continue
			}
			all = append(all, withHeaderValues(k, v))
		}
	}
	for _, cookies := range [][]*http.Cookie{client.Cookies, operation.Cookies} {
		for _, c := range cookies {
			all = append(all, probe.WithCookie(c))
		}
	}
	all = append(all, mutators...)

	return probe.NewRequest(ctx, operation.Method, operation.URL.String(), bytes.NewReader(operation.Body), all...)
}

// requestClient returns the *request.Client this operation's requests are
// built from and sent through.
func (operation *Operation) requestClient() *request.Client {
	if operation.Client == nil {
		return request.GetDefaultClient()
	}
	return operation.Client
}

// HTTPClient returns the *http.Client this operation's requests should be
// sent through.
func (operation *Operation) HTTPClient() *http.Client {
	return operation.requestClient().Client
}

// UserAgent returns the User-Agent this operation's requests are sent with.
func (operation *Operation) UserAgent() string {
	client := operation.requestClient()
	if ua := client.Header.Get("User-Agent"); ua != "" {
		return ua
	}
	return client.GetUserAgent()
}

func (operation *Operation) GetSecuritySchemes() []*auth.SecurityScheme {
	if operation.SecuritySchemes == nil {
		return []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}
	}
	return operation.SecuritySchemes
}

func (operation *Operation) GetSecurityScheme() *auth.SecurityScheme {
	if len(operation.SecuritySchemes) == 0 {
		return auth.MustNewNoAuthSecurityScheme()
	}
	return operation.SecuritySchemes[0]
}

func (operation *Operation) SetSecuritySchemes(securitySchemes []*auth.SecurityScheme) *Operation {
	operation.SecuritySchemes = securitySchemes
	return operation
}

func (operation *Operation) GetPath() string {
	return operation.URL.Path
}

func (operation *Operation) GetOpenAPIDocPath() *string {
	return operation.OpenAPIDocPath
}

func (operation *Operation) SetID(id string) *Operation {
	operation.ID = id
	return operation
}

func (operation *Operation) GenerateID() *Operation {
	operation.SetID(GenerateOperationID(operation.Method, operation.URL.Path))
	return operation
}

func (operation *Operation) GetID() string {
	return operation.ID
}

// Clone returns a copy of the operation whose URL, body, header, cookies and
// security scheme list can be changed without affecting the original. The
// client and the security schemes themselves are shared.
func (o *Operation) Clone() (*Operation, error) {
	u := o.URL
	if o.URL.User != nil {
		user := *o.URL.User
		u.User = &user
	}

	var cookies []*http.Cookie
	if o.Cookies != nil {
		cookies = make([]*http.Cookie, len(o.Cookies))
		for i, c := range o.Cookies {
			cookie := *c
			cookies[i] = &cookie
		}
	}

	var openAPIDocPath *string
	if o.OpenAPIDocPath != nil {
		docPath := *o.OpenAPIDocPath
		openAPIDocPath = &docPath
	}

	return &Operation{
		Client: o.Client,

		OpenAPIDocPath: openAPIDocPath,

		Method:          o.Method,
		URL:             u,
		Body:            bytes.Clone(o.Body),
		Cookies:         cookies,
		Header:          o.Header.Clone(),
		SecuritySchemes: slices.Clone(o.SecuritySchemes),

		ID: o.ID,
	}, nil
}
