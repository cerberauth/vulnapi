package request

import (
	"net"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/getkin/kin-openapi/openapi3"
)

type Operations []*Operation

func (o Operations) Len() int      { return len(o) }
func (o Operations) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o Operations) Less(i, j int) bool {
	if o[i].Path == o[j].Path {
		return o[i].Method < o[j].Method
	}

	return o[i].Path < o[j].Path
}

type Operation struct {
	*Request `json:"-" yaml:"-"`

	ID     string   `json:"id" yaml:"id"`
	Tags   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Method string   `json:"method" yaml:"method"`
	Path   string   `json:"path" yaml:"path"`

	SecuritySchemes []auth.SecurityScheme `json:"security_schemes" yaml:"security_schemes"`
}

func NewOperation(client *Client, method string, url string) (*Operation, error) {
	r, err := NewRequest(client, method, url, nil)
	if err != nil {
		return nil, err
	}

	return NewOperationFromRequest(r), nil
}

func (operation *Operation) IsReachable() error {
	host := operation.Request.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if operation.Request.URL.Scheme == "http" {
			host += ":80"
		} else if operation.Request.URL.Scheme == "https" {
			host += ":443"
		}
	}

	_, err := net.DialTimeout("tcp", host, operation.Request.Client.Timeout)
	return err
}

func NewOperationFromRequest(r *Request) *Operation {
	return &Operation{
		Request: r,

		ID:     r.URL.String(),
		Tags:   []string{},
		Method: r.Method,
		Path:   r.URL.Path,

		SecuritySchemes: []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()},
	}
}

func (operation *Operation) WithOpenapiOperation(path string, openapiOperation openapi3.Operation) *Operation {
	operation.SetPath(path)
	operation.SetID(openapiOperation.OperationID)
	operation.SetTags(openapiOperation.Tags)

	return operation
}

func (operation *Operation) GetRequest() *Request {
	return operation.Request
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

func (operation *Operation) SetPath(path string) *Operation {
	operation.Path = path

	return operation
}

func (operation *Operation) GetPath() string {
	return operation.Path
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
	o.Request = o.Request.Clone(o.Request.Context())

	var clonedSecuritySchemes []auth.SecurityScheme
	if o.SecuritySchemes != nil {
		clonedSecuritySchemes = make([]auth.SecurityScheme, len(o.SecuritySchemes))
		copy(clonedSecuritySchemes, o.SecuritySchemes)
	}

	return NewOperationFromRequest(o.Request).SetSecuritySchemes(clonedSecuritySchemes)
}
