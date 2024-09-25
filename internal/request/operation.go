package request

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/getkin/kin-openapi/openapi3"
)

type Operations []*Operation

func (o Operations) Len() int      { return len(o) }
func (o Operations) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o Operations) Less(i, j int) bool {
	if o[i].URL == o[j].URL {
		return o[i].Method < o[j].Method
	}

	return o[i].URL.String() < o[j].URL.String()
}

type Operation struct {
	*Client `json:"-" yaml:"-"`

	Method          string                `json:"method" yaml:"method"`
	URL             url.URL               `json:"url,string" yaml:"url,string"`
	Body            *bytes.Buffer         `json:"body,omitempty" yaml:"body,omitempty"`
	Cookies         []*http.Cookie        `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Header          http.Header           `json:"header,omitempty" yaml:"header,omitempty"`
	SecuritySchemes []auth.SecurityScheme `json:"security_schemes" yaml:"security_schemes"`

	ID   string   `json:"id" yaml:"id"`
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

func NewOperation(method string, operationUrl string, body *bytes.Buffer, client *Client) (*Operation, error) {
	if client == nil {
		client = DefaultClient
	}

	parsedUrl, err := url.Parse(operationUrl)
	if err != nil {
		return nil, err
	}

	return &Operation{
		Client: client,

		Method:          method,
		URL:             *parsedUrl,
		Body:            body,
		Cookies:         []*http.Cookie{},
		Header:          http.Header{},
		SecuritySchemes: []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()},
	}, nil
}

func (operation *Operation) IsReachable() error {
	host := operation.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if operation.URL.Scheme == "http" {
			host += ":80"
		} else if operation.URL.Scheme == "https" {
			host += ":443"
		} else {
			return errors.New("unsupported scheme")
		}
	}

	_, err := net.DialTimeout("tcp", host, operation.Client.Timeout)
	return err
}

func NewOperationFromRequest(r *Request) *Operation {
	var body bytes.Buffer
	if r.Body != nil {
		tee := io.TeeReader(r.Body, &body)
		io.ReadAll(tee)
	}

	return &Operation{
		ID:     r.URL.String(),
		Tags:   []string{},
		Method: r.Method,
		URL:    *r.URL,
		Body:   &body,

		SecuritySchemes: []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()},
	}
}

func (operation *Operation) WithOpenapiOperation(openapiOperation openapi3.Operation) *Operation {
	operation.SetID(openapiOperation.OperationID)
	operation.SetTags(openapiOperation.Tags)
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

func (operation *Operation) NewRequest() (*Request, error) {
	body := bytes.NewBuffer(nil)
	if operation.Body != nil && operation.Body.Len() > 0 {
		body.Write(operation.Body.Bytes())
	}
	req, err := NewRequest(operation.Method, operation.URL.String(), body, operation.Client)
	if err != nil {
		return nil, err
	}

	req.WithHeader(operation.Header).WithCookies(operation.Cookies)

	return req, nil
}

func (operation *Operation) GetSecuritySchemes() []auth.SecurityScheme {
	if operation.SecuritySchemes == nil {
		return []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	}
	return operation.SecuritySchemes
}

func (operation *Operation) SetSecuritySchemes(securitySchemes []auth.SecurityScheme) *Operation {
	operation.SecuritySchemes = securitySchemes
	return operation
}

func (operation *Operation) GetPath() string {
	return operation.URL.Path
}

func (operation *Operation) SetID(id string) *Operation {
	operation.ID = id
	return operation
}

func (operation *Operation) GetID() string {
	return operation.ID
}

func (operation *Operation) SetTags(tags []string) *Operation {
	operation.Tags = tags
	return operation
}

func (operation *Operation) GetTags() []string {
	return operation.Tags
}

func (o *Operation) Clone() *Operation {
	var clonedSecuritySchemes []auth.SecurityScheme
	if o.SecuritySchemes != nil {
		clonedSecuritySchemes = make([]auth.SecurityScheme, len(o.SecuritySchemes))
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

		ID:   o.ID,
		Tags: o.Tags,
	}
}
