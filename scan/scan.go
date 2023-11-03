package scan

import (
	"errors"
	"fmt"
	"log"

	"github.com/cerberauth/vulnapi/internal/auth"
	restapi "github.com/cerberauth/vulnapi/internal/rest_api"
	"github.com/cerberauth/vulnapi/report"
	"github.com/getkin/kin-openapi/openapi3"
)

type ScanHandler func(url string, ss auth.SecurityScheme) (*report.ScanReport, error)

type ScanOptions struct {
	Url              string
	OpenAPIUrlOrPath string
}

type Scan struct {
	opts            ScanOptions
	openAPIDoc      *openapi3.T
	securitySchemes []auth.SecurityScheme
	pendingScans    []ScanHandler
	reporter        *report.Reporter
}

func NewScanner(opts ScanOptions) (*Scan, error) {
	var openAPIDoc *openapi3.T
	if opts.OpenAPIUrlOrPath != "" {
		doc, err := restapi.LoadOpenAPI(opts.OpenAPIUrlOrPath)
		if err != nil {
			return nil, err
		}

		openAPIDoc = doc
	}

	return &Scan{
		opts:       opts,
		openAPIDoc: openAPIDoc,
		reporter:   report.NewReporter(),
	}, nil
}

func (s *Scan) AddSecurityScheme(ss auth.SecurityScheme) {
	s.securitySchemes = append(s.securitySchemes, ss)
}

func (s *Scan) AddPendingScanHandler(sh ScanHandler) *Scan {
	s.pendingScans = append(s.pendingScans, sh)

	return s
}

func (s *Scan) Execute() (*report.Reporter, []error, error) {
	if len(s.securitySchemes) == 0 {
		return nil, nil, errors.New("no security schemes has been configured")
	}

	if err := s.ValidateRequest(); err != nil {
		return nil, nil, err
	}

	log.Println("starting scan")

	var errors []error
	for i := 0; i < len(s.pendingScans); i++ {
		rep, err := s.pendingScans[i](s.opts.Url, s.securitySchemes[0])

		if err != nil {
			errors = append(errors, err)
		} else if rep != nil {
			s.reporter.AddReport(rep)
		}
	}

	return s.reporter, errors, nil
}

func (s *Scan) ValidateRequest() error {
	log.Println("validating request")

	r := restapi.ScanRestAPI(s.opts.Url, s.securitySchemes[0])
	if r.Err != nil {
		return r.Err
	}

	if r.Response.StatusCode >= 300 {
		return fmt.Errorf("the request with the passed JWT should return 2xx status code")
	}

	return nil
}
