package restapi

import (
	"fmt"
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

func ScanRestAPI(o *auth.Operation, ss auth.SecurityScheme) *report.VulnerabilityScanAttempt {
	var req *http.Request
	var res *http.Response
	var err error = nil

	client := &http.Client{}
	req, err = request.NewRequest(o.Method, o.Url)
	if err != nil {
		err = fmt.Errorf("request with url %s has an unexpected error", err)
	} else {
		req, res, err = request.DoRequest(client, req, ss)
	}

	if err != nil {
		err = fmt.Errorf("request with url %s has an unexpected error", err)
	} else if res.StatusCode < 200 && res.StatusCode >= 300 {
		err = fmt.Errorf("unexpected status code %d during test request", res.StatusCode)
	}

	return &report.VulnerabilityScanAttempt{
		Request:  req,
		Response: res,
		Err:      err,
	}
}
