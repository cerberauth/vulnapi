package scan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/config"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

func oauth2TokenURL(doc *openapi.OpenAPI, schemeName string, password bool) string {
	if doc.Doc.Components == nil {
		return ""
	}
	scheme, ok := doc.Doc.Components.SecuritySchemes[schemeName]
	if !ok || scheme.Value == nil || scheme.Value.Flows == nil {
		return ""
	}
	flow := scheme.Value.Flows.ClientCredentials
	if password {
		flow = scheme.Value.Flows.Password
	}
	if flow == nil {
		return ""
	}
	return flow.TokenURL
}

func identitySchemeValues(ctx context.Context, cfg *config.Config, doc *openapi.OpenAPI, client *request.Client) (map[string]string, error) {
	if cfg == nil || len(cfg.Identities) == 0 {
		return nil, nil
	}
	name, identity := cfg.DefaultIdentity()
	if identity == nil {
		return nil, errors.New("identities: several identities are declared, name the one to scan with \"default\"")
	}
	values := make(map[string]string, len(identity.Schemes))
	for schemeName, credential := range identity.Schemes {
		password := credential.OAuth2 != nil && credential.OAuth2.Username != nil
		value, err := credential.Resolve(ctx, client.Client, oauth2TokenURL(doc, schemeName, password))
		if err != nil {
			return nil, fmt.Errorf("identities.%s.schemes.%s: %w", name, schemeName, err)
		}
		values[schemeName] = value
	}
	return values, nil
}

func NewOpenAPIScanCmd() (scanCmd *cobra.Command) {
	var (
		securitySchemesValueArg map[string]string
		tokenStdin              bool
		serverUrl               string
	)

	scanCmd = &cobra.Command{
		Use:   "openapi [OpenAPIPath]",
		Short: "OpenAPI Operations Scan",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			settings := resolveSettings(cmd)
			target := settings.Target()

			openapiUrlOrPath := targetArg(cmd, args, func(s *internalCmd.ScanSettings) string {
				if target != nil {
					return target.OpenAPI
				}
				return ""
			}, settings, "OpenAPI")

			doc, err := openapi.LoadOpenAPI(ctx, openapiUrlOrPath)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-loading-openapi"))
			}

			if serverUrl == "" && target != nil {
				serverUrl = target.Server
			}
			if serverUrl != "" {
				baseUrl, err := url.Parse(serverUrl)
				if err != nil || baseUrl.Scheme == "" || baseUrl.Host == "" {
					telemetryx.Fatal(cmd, telemetryx.Reason(fmt.Errorf("invalid --server-url %q: an absolute URL is required", serverUrl), "invalid-server-url"))
				}
				if baseUrl.Path == "" {
					baseUrl.Path = "/"
				}
				doc.SetBaseUrl(baseUrl)
			}

			if err := doc.Validate(ctx); err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-openapi"))
			}

			var validToken *string
			switch {
			case tokenStdin:
				validToken, err = readToken(os.Stdin)
				if err != nil {
					telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-reading-token-from-stdin"))
				}
			case !cmd.Flags().Changed("token-stdin") && isStdinOpen():
				// Deprecated: reading a piped token without --token-stdin.
				// Pass --token-stdin=false to skip it, e.g. in CI where
				// stdin can be an open pipe that never closes.
				if validToken, err = readToken(os.Stdin); err == nil {
					cmd.PrintErrln("Warning: reading the token from stdin without --token-stdin is deprecated; pass --token-stdin")
				}
			}

			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-creating-http-client"))
			}
			flagHeaders, cookies, err := cobracurl.BuildRequestHeaders(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-building-request-headers"))
			}
			headers, err := settings.TargetHeaders(ctx, flagHeaders)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-configuration"))
			}
			client = client.WithHeader(headers).WithCookies(cookies)
			credentials, err := internalCmd.ApplyAuthFlags(cmd, client, settings)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-auth-flags"))
			}
			request.SetDefaultClient(client)

			identityValues, err := identitySchemeValues(ctx, settings.Config, doc, client)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-identity"))
			}
			values := make(map[string]interface{}, len(identityValues)+len(securitySchemesValueArg))
			for key, value := range identityValues {
				if key == config.AllSchemes {
					if validToken == nil {
						validToken = &value
					}
					continue
				}
				values[key] = &value
			}
			for key, value := range securitySchemesValueArg {
				values[key] = &value
			}
			securitySchemesValues := openapi.NewSecuritySchemeValues(values).WithDefault(validToken).WithCredentials(credentials)

			internalCmd.ApplyJWTSecretFlag(cmd)

			s, err := scenario.NewOpenAPIScan(ctx, harnessx.New(), doc, securitySchemesValues, client, settings.ScanOptions())
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-scenario"))
			}
			executeScan(cmd, s, settings)
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	internalCmd.AddAuthFlags(scanCmd)
	scanCmd.Flags().StringToStringVarP(&securitySchemesValueArg, "security-schemes", "", nil, "Value for each security scheme: a token, an API key, or user:password for HTTP Basic")
	scanCmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "Read the default security scheme token from stdin")
	scanCmd.Flags().StringVar(&serverUrl, "server-url", "", "Base URL of the API, overriding the servers of the OpenAPI document")
	return scanCmd
}
