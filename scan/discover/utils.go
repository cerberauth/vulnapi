package discover

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

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

// scanURLsConcurrency is how many URLs ScanURLs probes at once.
const scanURLsConcurrency = 20

// ScanURLs probes scanUrls (resolved against op's base URL) concurrently and
// returns a *finding.Finding naming every URL that responded 200 OK, or nil
// if none did. The decisive Attempt is the first exposed URL in scanUrls
// order. Requests that fail are skipped; an error is returned only when
// every request failed.
func ScanURLs(ctx context.Context, scanUrls []string, op *operation.Operation, securityScheme *auth.SecurityScheme) (*finding.Finding, error) {
	base := ExtractBaseURL(&op.URL)
	attempts := make([]*finding.Attempt, len(scanUrls))
	errs := make([]error, len(scanUrls))

	var wg sync.WaitGroup
	sem := make(chan struct{}, scanURLsConcurrency)
	for i, path := range scanUrls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}

			newOperation, err := operation.NewOperation(http.MethodGet, base.ResolveReference(&url.URL{Path: path}).String(), nil, op.Client)
			if err != nil {
				errs[i] = err
				return
			}
			newOperation.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})

			attempts[i], errs[i] = finding.Fetch(ctx, newOperation, securityScheme)
		}()
	}
	wg.Wait()

	var exposedURLs []string
	var decisiveAttempt *finding.Attempt
	var failed []error
	for i, attempt := range attempts {
		if errs[i] != nil {
			failed = append(failed, errs[i])
			continue
		}
		if attempt.Response.GetStatusCode() == http.StatusOK { // TODO: check if the response contains the expected content
			exposedURLs = append(exposedURLs, attempt.Request.URL.String())
			if decisiveAttempt == nil {
				decisiveAttempt = attempt
			}
		}
	}

	if len(failed) > 0 && len(failed) == len(scanUrls) {
		return nil, fmt.Errorf("all %d requests failed: %w", len(failed), failed[0])
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
