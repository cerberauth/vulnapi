package operation

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

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

	_, err := net.DialTimeout("tcp", host, operation.Client.Timeout)
	return err
}

func NewOperationFromRequest(r *request.Request) (*Operation, error) {
	return &Operation{
		ID:      r.GetURL(),
		Method:  r.GetMethod(),
		URL:     *r.HttpRequest.URL,
		Header:  r.GetHeader(),
		Cookies: r.GetCookies(),
		Body:    r.GetBody(),

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

func (operation *Operation) NewRequest() (*request.Request, error) {
	req, err := request.NewRequest(operation.Method, operation.URL.String(), bytes.NewReader(operation.Body), operation.Client)
	if err != nil {
		return nil, err
	}

	req.WithHeader(operation.Header).WithCookies(operation.Cookies)

	return req, nil
}

func (operation *Operation) GetSecuritySchemes() []*auth.SecurityScheme {
	if operation.SecuritySchemes == nil {
		return []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}
	}
	return operation.SecuritySchemes
}

func (operation *Operation) GetSecurityScheme() *auth.SecurityScheme {
	if operation.SecuritySchemes == nil {
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

func (o *Operation) Clone() (*Operation, error) {
	var clonedSecuritySchemes []*auth.SecurityScheme
	if o.SecuritySchemes != nil {
		clonedSecuritySchemes = make([]*auth.SecurityScheme, len(o.SecuritySchemes))
		copy(clonedSecuritySchemes, o.SecuritySchemes)
	}

	return &Operation{
		Client: o.Client,

		Method:          o.Method,
		URL:             o.URL,
		Body:            o.Body,
		Cookies:         o.Cookies,
		Header:          o.Header,
		SecuritySchemes: clonedSecuritySchemes,

		ID: o.ID,
	}, nil
}
