package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxSpecSize = 16 << 20

var headerNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

func jsonRaw(b []byte) any { return json.RawMessage(b) }

func ptr[T any](v T) *T { return &v }

// Inputs carry no credential: header_env, token_env and scheme_env hold the
// names of environment variables.

type scanOpenAPIInput struct {
	Spec       string            `json:"spec" jsonschema:"URL or path of the OpenAPI document. A path is resolved inside the spec root directory of the server."`
	ServerURL  string            `json:"server_url,omitempty" jsonschema:"Base URL of the API, overriding the servers of the document. Its host must be on the allow-list."`
	TokenEnv   string            `json:"token_env,omitempty" jsonschema:"Name of the environment variable holding the default token for the security schemes of the document, with or without a Bearer prefix."`
	SchemeEnv  map[string]string `json:"scheme_env,omitempty" jsonschema:"Security scheme name to the name of the environment variable holding its value."`
	HeaderEnv  map[string]string `json:"header_env,omitempty" jsonschema:"Header name to the name of the environment variable holding the full header value, for example Authorization to VULNAPI_TOKEN."`
	IncludeIDs []string          `json:"include_scans,omitempty" jsonschema:"Run only the checks matching these IDs or patterns, for example jwt.*. See list_checks."`
	ExcludeIDs []string          `json:"exclude_scans,omitempty" jsonschema:"Skip the checks matching these IDs or patterns."`
}

type scanEndpointInput struct {
	URL        string            `json:"url" jsonschema:"Endpoint to scan, starting with http:// or https://. Its host must be on the allow-list."`
	Method     string            `json:"method,omitempty" jsonschema:"HTTP method, GET (default), HEAD or OPTIONS."`
	HeaderEnv  map[string]string `json:"header_env,omitempty" jsonschema:"Header name to the name of the environment variable holding the full header value, for example Authorization to VULNAPI_TOKEN."`
	IncludeIDs []string          `json:"include_scans,omitempty" jsonschema:"Run only the checks matching these IDs or patterns, for example jwt.*. See list_checks."`
	ExcludeIDs []string          `json:"exclude_scans,omitempty" jsonschema:"Skip the checks matching these IDs or patterns."`
}

type scanGraphQLInput struct {
	URL        string            `json:"url" jsonschema:"GraphQL endpoint, starting with http:// or https://. Its host must be on the allow-list."`
	HeaderEnv  map[string]string `json:"header_env,omitempty" jsonschema:"Header name to the name of the environment variable holding the full header value, for example Authorization to VULNAPI_TOKEN."`
	IncludeIDs []string          `json:"include_scans,omitempty" jsonschema:"Run only the checks matching these IDs or patterns. See list_checks."`
	ExcludeIDs []string          `json:"exclude_scans,omitempty" jsonschema:"Skip the checks matching these IDs or patterns."`
}

type discoverAPIInput struct {
	URL       string            `json:"url" jsonschema:"Base URL of the API to discover, starting with http:// or https://. Its host must be on the allow-list."`
	HeaderEnv map[string]string `json:"header_env,omitempty" jsonschema:"Header name to the name of the environment variable holding the full header value."`
}

type listChecksInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"Only list checks whose ID, name or tags contain this text."`
}

type explainFindingInput struct {
	ID string `json:"id" jsonschema:"Check or finding ID, for example the id of a finding in a scan report."`
}

// CheckInfo is the metadata of one check.
type CheckInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	CVSSScore   float64  `json:"cvss_score"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	CWE         string   `json:"cwe_id,omitempty"`
	CAPEC       string   `json:"capec_id,omitempty"`
	OWASP       string   `json:"owasp,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Docs        string   `json:"docs,omitempty"`
}

type listChecksOutput struct {
	Checks []CheckInfo `json:"checks"`
}

func checkInfo(def checkdef.CheckDef) CheckInfo {
	return CheckInfo{
		ID: def.ID, Name: def.Name, Description: def.Description,
		CVSSScore: def.CVSSScore, CVSSVector: def.CVSSVector,
		CWE: def.CWEID, CAPEC: def.CAPECID, OWASP: def.OWASP,
		Tags: def.Tags, Docs: def.Link,
	}
}

func (s *Server) registerTools() {
	scanAnnotations := &mcp.ToolAnnotations{
		DestructiveHint: ptr(false),
		OpenWorldHint:   ptr(true),
	}
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "scan_openapi",
		Description: "Scan every operation of an OpenAPI document. Sends requests to the API server, which must be on the allow-list. Returns the report as structured content.",
		Annotations: scanAnnotations,
	}, s.scanOpenAPI)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "scan_curl",
		Description: "Scan a single endpoint with a safe HTTP method. The host must be on the allow-list. Returns the report as structured content.",
		Annotations: scanAnnotations,
	}, s.scanCurl)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "scan_graphql",
		Description: "Scan a GraphQL endpoint. The host must be on the allow-list. Returns the report as structured content.",
		Annotations: scanAnnotations,
	}, s.scanGraphQL)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "discover_api",
		Description: "Look for well-known paths, exposed files, OpenAPI and GraphQL endpoints and technology fingerprints of an API. The host must be on the allow-list.",
		Annotations: scanAnnotations,
	}, s.discoverAPI)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_checks",
		Description: "List the security checks VulnAPI can run, with their severity and OWASP mapping.",
		Annotations: readOnly,
	}, s.listChecks)
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "explain_finding",
		Description: "Describe a check or finding ID: what it detects, severity, CWE and OWASP mapping and documentation link.",
		Annotations: readOnly,
	}, s.explainFinding)
}

func (s *Server) scanOpenAPI(ctx context.Context, req *mcp.CallToolRequest, in scanOpenAPIInput) (*mcp.CallToolResult, any, error) {
	doc, err := s.loadSpec(ctx, in.Spec)
	if err != nil {
		return nil, nil, err
	}

	if in.ServerURL != "" {
		baseURL, err := s.parseTargetURL(in.ServerURL)
		if err != nil {
			return nil, nil, fmt.Errorf("server_url: %w", err)
		}
		if baseURL.Path == "" {
			baseURL.Path = "/"
		}
		doc.SetBaseUrl(baseURL)
	}
	base := doc.BaseUrl()
	if base == nil {
		return nil, nil, errors.New("the document has no usable server: set server_url")
	}
	if err := s.opts.AllowHosts.CheckURL(base); err != nil {
		return nil, nil, fmt.Errorf("API server of the document: %w", err)
	}
	if err := doc.Validate(ctx); err != nil {
		return nil, nil, fmt.Errorf("invalid OpenAPI document: %w", err)
	}

	values := make(map[string]interface{}, len(in.SchemeEnv))
	for scheme, envName := range in.SchemeEnv {
		value, err := s.opts.Env.Resolve(envName)
		if err != nil {
			return nil, nil, err
		}
		values[scheme] = &value
	}
	var defaultToken *string
	if in.TokenEnv != "" {
		token, err := s.opts.Env.Resolve(in.TokenEnv)
		if err != nil {
			return nil, nil, err
		}
		// the variable may hold an Authorization header value
		if len(token) > len("bearer ") && strings.EqualFold(token[:len("bearer ")], "bearer ") {
			token = strings.TrimSpace(token[len("bearer "):])
		}
		defaultToken = &token
	}

	return s.runScan(ctx, req, scanRequest{
		headerEnv:  in.HeaderEnv,
		include:    in.IncludeIDs,
		exclude:    in.ExcludeIDs,
		targetHost: base.Host,
		build: func(client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
			// The security scheme values hold the credentials resolved above;
			// the options and values are built per call, so nothing leaks
			// into the next scan.
			schemeValues := openapi.NewSecuritySchemeValues(values).WithDefault(defaultToken)
			return scenario.NewOpenAPIScan(ctx, harnessx.New(), doc, schemeValues, client, opts)
		},
	})
}

func (s *Server) scanCurl(ctx context.Context, req *mcp.CallToolRequest, in scanEndpointInput) (*mcp.CallToolResult, any, error) {
	u, err := s.parseTargetURL(in.URL)
	if err != nil {
		return nil, nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	switch method {
	case "":
		method = http.MethodGet
	case http.MethodGet, http.MethodHead, http.MethodOptions:
	default:
		return nil, nil, fmt.Errorf("method %s is not available: use GET, HEAD or OPTIONS", method)
	}

	return s.runScan(ctx, req, scanRequest{
		headerEnv:  in.HeaderEnv,
		include:    in.IncludeIDs,
		exclude:    in.ExcludeIDs,
		targetHost: u.Host,
		build: func(client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
			return scenario.NewURLScan(harnessx.New(), method, u, "", client, opts)
		},
	})
}

func (s *Server) scanGraphQL(ctx context.Context, req *mcp.CallToolRequest, in scanGraphQLInput) (*mcp.CallToolResult, any, error) {
	u, err := s.parseTargetURL(in.URL)
	if err != nil {
		return nil, nil, err
	}
	return s.runScan(ctx, req, scanRequest{
		headerEnv:  in.HeaderEnv,
		include:    in.IncludeIDs,
		exclude:    in.ExcludeIDs,
		targetHost: u.Host,
		build: func(client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
			return scenario.NewGraphQLScan(harnessx.New(), u, client, opts)
		},
	})
}

func (s *Server) discoverAPI(ctx context.Context, req *mcp.CallToolRequest, in discoverAPIInput) (*mcp.CallToolResult, any, error) {
	u, err := s.parseTargetURL(in.URL)
	if err != nil {
		return nil, nil, err
	}
	return s.runScan(ctx, req, scanRequest{
		headerEnv:  in.HeaderEnv,
		targetHost: u.Host,
		build: func(client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
			opts.Title = "API Discovery"
			return scenario.NewDiscoverAPIScan(harnessx.New(), http.MethodGet, u, client, opts)
		},
	})
}

func (s *Server) listChecks(_ context.Context, _ *mcp.CallToolRequest, in listChecksInput) (*mcp.CallToolResult, listChecksOutput, error) {
	defs, err := scenario.CheckCatalog()
	if err != nil {
		return nil, listChecksOutput{}, err
	}
	filter := strings.ToLower(strings.TrimSpace(in.Filter))
	out := listChecksOutput{Checks: []CheckInfo{}}
	var text strings.Builder
	for _, def := range defs {
		info := checkInfo(def)
		if filter != "" && !strings.Contains(strings.ToLower(info.ID+" "+info.Name+" "+info.Description+" "+strings.Join(info.Tags, " ")), filter) {
			continue
		}
		out.Checks = append(out.Checks, info)
		fmt.Fprintf(&text, "%s\t%s\t%.1f\n", info.ID, info.Name, info.CVSSScore)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%d checks (id, name, CVSS score):\n%s", len(out.Checks), text.String())}}}, out, nil
}

func (s *Server) explainFinding(_ context.Context, _ *mcp.CallToolRequest, in explainFindingInput) (*mcp.CallToolResult, CheckInfo, error) {
	defs, err := scenario.CheckCatalog()
	if err != nil {
		return nil, CheckInfo{}, err
	}
	id := strings.TrimSpace(in.ID)
	for _, def := range defs {
		if def.ID == id {
			info := checkInfo(def)
			text := fmt.Sprintf("%s: %s\nCVSS %.1f, %s, %s\n%s\nDocs: %s", info.ID, info.Name, info.CVSSScore, info.CWE, info.OWASP, info.Description, info.Docs)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, info, nil
		}
	}
	return nil, CheckInfo{}, fmt.Errorf("unknown check ID %q: use list_checks", id)
}

// loadSpec loads an OpenAPI document from an allowed URL or from a file inside
// the spec root. Remote documents are fetched by the loader, outside the guard
// transport, so their host is checked here first.
func (s *Server) loadSpec(ctx context.Context, spec string) (*openapi.OpenAPI, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("spec is required")
	}

	// Same rule as openapi.LoadOpenAPI: a value with a host is a URL.
	if u, err := url.Parse(spec); err == nil && u.Hostname() != "" {
		remote, err := s.parseTargetURL(spec)
		if err != nil {
			return nil, fmt.Errorf("spec: %w", err)
		}
		return openapi.LoadOpenAPI(ctx, remote.String())
	}

	path, err := s.resolveSpecPath(spec)
	if err != nil {
		return nil, err
	}
	return openapi.LoadOpenAPI(ctx, path)
}

func (s *Server) resolveSpecPath(spec string) (string, error) {
	path := spec
	if !filepath.IsAbs(path) {
		path = filepath.Join(s.opts.SpecRoot, path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("spec: cannot read %q", spec)
	}
	rel, err := filepath.Rel(s.opts.SpecRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("spec: %q is outside the spec root", spec)
	}
	switch strings.ToLower(filepath.Ext(resolved)) {
	case ".json", ".yaml", ".yml":
	default:
		return "", errors.New("spec: only .json, .yaml and .yml files can be loaded")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("spec: cannot read %q", spec)
	}
	if info.Size() > maxSpecSize {
		return "", errors.New("spec: file is too large")
	}
	return resolved, nil
}
