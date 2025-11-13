package scenario

import (
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
)

var commonHostnames = []string{"www", "api", "graphql", "graph", "app", "auth", "login", "oauth", "admin", "dashboard", "dev", "staging", "test", "stage", "prod", "production", "uat", "qa", "sandbox", "old", "demo", "blog", "forum", "community", "calendar", "contacts", "chat", "support", "help", "docs"}

func searchByCommonHostnames(domain string) []string {
	subdomains := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, hostname := range commonHostnames {
		wg.Add(1)
		go func(hostname string) {
			defer wg.Done()
			subdomain := hostname + "." + domain
			_, err := net.LookupIP(subdomain)
			if err != nil {
				return
			}

			mu.Lock()
			subdomains = append(subdomains, subdomain)
			mu.Unlock()
		}(hostname)
	}

	wg.Wait()
	return subdomains
}

func searchByLookupIP(rootDomain string) ([]string, error) {
	subdomains := []string{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	ips, err := net.LookupIP(rootDomain)
	if err != nil {
		return subdomains, err
	}

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			hosts, err := net.LookupAddr(ip.String())
			if err != nil {
				return
			}

			for _, host := range hosts {
				if len(host) == 0 {
					continue
				}
				subdomain := host[:len(host)-1] // Remove the trailing dot

				mu.Lock()
				subdomains = append(subdomains, subdomain)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return subdomains, nil
}

func getAllFQDNs(domain string) []string {
	fqdns := []string{domain}

	subdomains := searchByCommonHostnames(domain)
	fqdns = append(fqdns, subdomains...)

	for _, subdomain := range subdomains {
		subdomains, err := searchByLookupIP(subdomain)
		if err != nil {
			continue
		}

		fqdns = append(fqdns, subdomains...)
	}

	return fqdns
}

func testFqdnReachable(fqdn string, client *request.Client) (*operation.Operation, error) {
	op, err := operation.NewOperation(http.MethodGet, "https://"+fqdn, nil, client)
	if err != nil {
		return nil, err
	}

	if err := op.IsReachable(); err == nil {
		return op, nil
	}

	op, err = operation.NewOperation(http.MethodGet, "http://"+fqdn, nil, client)
	if err != nil {
		return nil, err
	}

	if err := op.IsReachable(); err == nil {
		return op, nil
	}

	return nil, nil
}

func NewDiscoverDomainsScan(rootDomain string, client *request.Client, opts *scan.ScanOptions) ([]*scan.Scan, error) {
	if client == nil {
		client = request.GetDefaultClient()
	}

	domains := getAllFQDNs(rootDomain)
	if len(domains) == 0 {
		return nil, errors.New("no subdomains found")
	}

	domainsScan := []*scan.Scan{}
	for _, domain := range domains {
		if op, err := testFqdnReachable(domain, client); op != nil && err == nil {
			domainScan, err := scan.NewScan(operation.Operations{op}, nil, opts)
			if err != nil {
				return nil, err
			}

			domainScan.AddScanHandler(scan.NewOperationScanHandler(fingerprint.DiscoverFingerPrintScanID, fingerprint.ScanHandler, []report.Issue{}))
			domainScan.AddScanHandler(scan.NewOperationScanHandler(discoverableopenapi.DiscoverableOpenAPIScanID, discoverableopenapi.ScanHandler, []report.Issue{}))
			domainScan.AddScanHandler(scan.NewOperationScanHandler(discoverablegraphql.DiscoverableGraphQLPathScanID, discoverablegraphql.ScanHandler, []report.Issue{}))
			domainsScan = append(domainsScan, domainScan)
		}
	}

	return domainsScan, nil
}
