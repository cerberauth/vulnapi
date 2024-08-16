package scenario

import (
	"errors"
	"net"
	"net/http"

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

	for _, hostname := range commonHostnames {
		subdomain := hostname + "." + domain
		_, err := net.LookupIP(subdomain)
		if err != nil {
			continue
		}

		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}

func searchByLookupIP(rootDomain string) ([]string, error) {
	subdomains := []string{}

	ips, err := net.LookupIP(rootDomain)
	if err != nil {
		return subdomains, err
	}

	for _, ip := range ips {
		hosts, err := net.LookupAddr(ip.String())
		if err != nil {
			continue
		}

		for _, host := range hosts {
			if len(host) == 0 {
				continue
			}
			subdomain := host[:len(host)-1] // Remove the trailing dot
			subdomains = append(subdomains, subdomain)
		}
	}

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

func testFqdnReachable(fqdn string, client *request.Client) (*request.Operation, error) {
	operation, err := request.NewOperation(client, http.MethodGet, "https://"+fqdn)
	if err != nil {
		return nil, err
	}

	if err := operation.IsReachable(); err == nil {
		return operation, nil
	}

	operation, err = request.NewOperation(client, http.MethodGet, "http://"+fqdn)
	if err != nil {
		return nil, err
	}

	if err := operation.IsReachable(); err == nil {
		return operation, nil
	}

	return nil, nil
}

func NewDiscoverDomainsScan(rootDomain string, client *request.Client, reporter *report.Reporter) ([]*scan.Scan, error) {
	if client == nil {
		client = request.DefaultClient
	}

	domains := getAllFQDNs(rootDomain)
	if len(domains) == 0 {
		return nil, errors.New("no subdomains found")
	}

	domainsScan := []*scan.Scan{}
	for _, domain := range domains {
		if operation, err := testFqdnReachable(domain, client); operation != nil && err == nil {
			domainScan, err := scan.NewScan(request.Operations{operation}, reporter)
			if err != nil {
				return nil, err
			}

			domainScan.AddScanHandler(fingerprint.ScanHandler).AddScanHandler(discoverableopenapi.ScanHandler).AddScanHandler(discoverablegraphql.ScanHandler)
			domainsScan = append(domainsScan, domainScan)
		}
	}

	return domainsScan, nil
}
