package request

import (
	"bytes"
	"io"
	"net/http"
)

type Response struct {
	Body         *bytes.Buffer
	HttpResponse *http.Response
}

func NewResponse(response *http.Response) (*Response, error) {
	if response == nil {
		return nil, NilResponseError()
	}

	if response.Body == nil {
		return &Response{
			Body:         nil,
			HttpResponse: response,
		}, nil
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		Body:         bytes.NewBuffer(body),
		HttpResponse: response,
	}, nil
}

func (response *Response) GetStatusCode() int {
	return response.HttpResponse.StatusCode
}

func (response *Response) GetBody() *bytes.Buffer {
	return response.Body
}

func (response *Response) GetHeader() http.Header {
	return response.HttpResponse.Header
}

func (response *Response) GetCookies() []*http.Cookie {
	return response.HttpResponse.Cookies()
}
