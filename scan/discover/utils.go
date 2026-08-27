package discover

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/seclist"
)

func ExtractBaseURL(inputURL *url.URL) *url.URL {
	return &url.URL{
		Scheme: inputURL.Scheme,
		Host:   inputURL.Host,
	}
}

// ScanURLs probes scanUrls (resolved against op's base URL) concurrently and
// returns a *finding.Finding naming every URL that responded 200 OK, or nil
// if none did. The decisive Attempt is the first exposed URL found.
func ScanURLs(ctx context.Context, scanUrls []string, op *operation.Operation, securityScheme *auth.SecurityScheme) (*finding.Finding, error) {
	base := ExtractBaseURL(&op.URL)
	chunkSize := 20
	results := make(chan *finding.Attempt, len(scanUrls))
	errs := make(chan error, len(scanUrls))

	for i := 0; i < len(scanUrls); i += chunkSize {
		end := i + chunkSize
		if end > len(scanUrls) {
			end = len(scanUrls)
		}
		chunk := scanUrls[i:end]

		go func(chunk []string) {
			for _, path := range chunk {
				newOperation, err := operation.NewOperation(http.MethodGet, base.ResolveReference(&url.URL{Path: path}).String(), nil, op.Client)
				newOperation.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})
				if err != nil {
					errs <- err
					return
				}

				attempt, err := finding.Fetch(ctx, newOperation, securityScheme)
				if err != nil {
					errs <- err
					return
				}

				results <- attempt
			}
		}(chunk)
	}

	var exposedURLs []string
	var decisiveAttempt *finding.Attempt
	for i := 0; i < len(scanUrls); i++ {
		select {
		case attempt := <-results:
			if attempt.Err != nil {
				errs <- attempt.Err
				continue
			}
			if attempt.Response.GetStatusCode() == http.StatusOK { // TODO: check if the response contains the expected content
				exposedURLs = append(exposedURLs, attempt.Request.URL.String())
				if decisiveAttempt == nil {
					decisiveAttempt = attempt
				}
			}
		case err := <-errs:
			log.Printf("Error scanning URL: %v", err)
			continue
		}
	}

	if len(exposedURLs) == 0 {
		return nil, nil
	}

	return &finding.Finding{
		Parameter: exposedURLs[0],
		Attempt:   decisiveAttempt,
		Extra: map[string]string{
			"discovered_urls":  strings.Join(exposedURLs, ", "),
			"discovered_count": strconv.Itoa(len(exposedURLs)),
		},
	}, nil
}

func DownloadAndScanURLs(ctx context.Context, name string, seclistUrl string, op *operation.Operation, securityScheme *auth.SecurityScheme) (*finding.Finding, error) {
	urlsFromSeclist, err := seclist.NewSecListFromURL(name, seclistUrl)
	if err != nil {
		return nil, err
	}

	return ScanURLs(ctx, urlsFromSeclist.Items, op, securityScheme)
}
