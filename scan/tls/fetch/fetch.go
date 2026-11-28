package tlsfetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/certificate"
	cipherstrength "github.com/cerberauth/proxyaudit/proxy/checks/tls/cipher_strength"
	httpsredirect "github.com/cerberauth/proxyaudit/proxy/checks/tls/https_redirect"
	protocolversion "github.com/cerberauth/proxyaudit/proxy/checks/tls/protocol_version"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan"
)

const CheckID harnessx.CheckID = "tls.fetch"

type Host struct {
	Address      string
	URL          string
	Operation    *operation.Operation
	Observations []harnessx.Observation
	SkipReasons  map[harnessx.CheckID]string
}

type Result struct {
	Hosts []*Host
}

var tlsChecks = []harnessx.Check{
	probebase.TLSInfoCheck,
	certificate.Check,
	protocolversion.Check,
	cipherstrength.Check,
	httpsredirect.Check,
}

func hostAddress(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
}

func distinctHosts(store harnessx.ResultStore) []*Host {
	loader, ok := store.Get(scan.OperationsLoaderCheckID)
	if !ok {
		return nil
	}
	byAddress := map[string]*Host{}
	for _, resource := range loader.Resources {
		op, ok := harnessx.ResourceDataAs[*operation.Operation](resource)
		if !ok {
			continue
		}
		address := hostAddress(&op.URL)
		if _, seen := byAddress[address]; seen {
			continue
		}
		origin := url.URL{Scheme: op.URL.Scheme, Host: op.URL.Host, Path: "/"}
		byAddress[address] = &Host{Address: address, URL: origin.String(), Operation: op}
	}
	hosts := make([]*Host, 0, len(byAddress))
	for _, host := range byAddress {
		hosts = append(hosts, host)
	}
	slices.SortFunc(hosts, func(a, b *Host) int { return strings.Compare(a.Address, b.Address) })
	return hosts
}

func inspect(ctx context.Context, host *Host) error {
	client := host.Operation.HTTPClient()
	target := scanctx.NewTarget(host.URL, &scanctx.ScanContext{HTTPClient: &http.Client{Transport: client.Transport, Timeout: client.Timeout}})
	engine := harnessx.New(harnessx.WithChecks(tlsChecks...))
	summary, err := engine.Run(ctx, target)
	if err != nil {
		return err
	}
	host.Observations = summary.Observations
	host.SkipReasons = map[harnessx.CheckID]string{}
	for _, result := range summary.Results {
		if result.Skipped {
			host.SkipReasons[result.CheckID] = result.SkipReason
		}
	}
	return nil
}

var Check = checkdef.NewCheck(
	checkdef.CheckDef{ID: string(CheckID), Name: "TLS Fetch", DependsOn: []string{string(scan.OperationsLoaderCheckID)}},
	func(ctx context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		hosts := distinctHosts(store)
		if len(hosts) == 0 {
			return harnessx.Result{Err: errors.New("tls.fetch: no operation to inspect")}, nil
		}
		for _, host := range hosts {
			if err := inspect(ctx, host); err != nil {
				return harnessx.Result{}, err
			}
		}
		return harnessx.DataResult(&Result{Hosts: hosts}), nil
	},
)

func (h *Host) findingFor(codes []string) *finding.Finding {
	var matched []string
	var evidence []string
	for _, observation := range h.Observations {
		code := observation.Metadata[probebase.MetadataCode]
		if !slices.Contains(codes, code) {
			continue
		}
		matched = append(matched, code)
		evidence = append(evidence, observation.Title+": "+observation.Evidence)
	}
	if len(matched) == 0 {
		return nil
	}
	return &finding.Finding{
		Parameter: h.Address,
		Operation: h.Operation,
		Extra: map[string]string{
			"host":     h.Address,
			"codes":    strings.Join(matched, ", "),
			"evidence": strings.Join(evidence, "; "),
		},
	}
}

func NewCodeCheck(def checkdef.CheckDef, source harnessx.CheckID, codes ...string) harnessx.Check {
	return checkdef.NewCheck(def,
		func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			result, ok := harnessx.GetData[*Result](store, CheckID)
			if !ok {
				return harnessx.Result{Err: errors.New(def.ID + ": missing tls.fetch result")}, nil
			}
			var findings []*finding.Finding
			for _, host := range result.Hosts {
				if f := host.findingFor(codes); f != nil {
					findings = append(findings, f)
				}
			}
			if len(findings) == 0 {
				return harnessx.Result{}, nil
			}
			return harnessx.DataResult(findings), nil
		},
		checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) string {
			result, ok := harnessx.GetData[*Result](store, CheckID)
			if !ok {
				return ""
			}
			var reasons []string
			for _, host := range result.Hosts {
				reason, skipped := host.SkipReasons[source]
				if !skipped {
					return ""
				}
				reasons = append(reasons, host.Address+": "+reason)
			}
			return strings.Join(reasons, "; ")
		})),
	)
}
