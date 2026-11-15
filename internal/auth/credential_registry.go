package auth

import (
	"net/http"
	"sync"
)

type CredentialOptions struct {
	ClientID     string
	ClientSecret string //nolint:gosec
	TokenURL     string
	Scopes       []string
	Username     string
	Password     string //nolint:gosec

	LoginCommand    string
	LoginURL        string
	LoginData       string
	LoginTokenField string

	HTTPClient *http.Client
}

type CredentialRegistry struct {
	options     CredentialOptions
	mu          sync.Mutex
	credentials map[string]*ManagedCredential
}

func NewCredentialRegistry(options CredentialOptions) *CredentialRegistry {
	return &CredentialRegistry{options: options, credentials: map[string]*ManagedCredential{}}
}

func (r *CredentialRegistry) Options() CredentialOptions {
	if r == nil {
		return CredentialOptions{}
	}
	return r.options
}

func (r *CredentialRegistry) get(key string, newSource func() CredentialSource) *ManagedCredential {
	r.mu.Lock()
	defer r.mu.Unlock()
	if credential, ok := r.credentials[key]; ok {
		return credential
	}
	credential := NewManagedCredential(newSource())
	r.credentials[key] = credential
	return credential
}

func (r *CredentialRegistry) HasLogin() bool {
	return r != nil && (r.options.LoginCommand != "" || r.options.LoginURL != "")
}

func (r *CredentialRegistry) Login() *ManagedCredential {
	if !r.HasLogin() {
		return nil
	}
	return r.get("login", func() CredentialSource {
		if r.options.LoginCommand != "" {
			return NewCommandSource(r.options.LoginCommand)
		}
		return NewHTTPLoginSource(r.options.LoginURL, r.options.LoginData, r.options.LoginTokenField, r.options.HTTPClient)
	})
}

func (r *CredentialRegistry) OAuth2(flow OAuthFlow, tokenURL string) *ManagedCredential {
	if r == nil || r.options.ClientID == "" {
		return nil
	}
	if r.options.TokenURL != "" {
		tokenURL = r.options.TokenURL
	}
	if tokenURL == "" {
		return nil
	}
	switch flow {
	case ClientCredentials:
		if r.options.Username != "" {
			return nil
		}
		return r.get(string(flow)+" "+tokenURL, func() CredentialSource {
			return NewOAuth2ClientCredentialsSource(tokenURL, r.options.ClientID, r.options.ClientSecret, r.options.Scopes, r.options.HTTPClient)
		})
	case PasswordFlow:
		if r.options.Username == "" {
			return nil
		}
		return r.get(string(flow)+" "+tokenURL, func() CredentialSource {
			return NewOAuth2PasswordSource(tokenURL, r.options.ClientID, r.options.ClientSecret, r.options.Username, r.options.Password, r.options.Scopes, r.options.HTTPClient)
		})
	}
	return nil
}

func (r *CredentialRegistry) Default() *ManagedCredential {
	if r == nil {
		return nil
	}
	if login := r.Login(); login != nil {
		return login
	}
	if r.options.Username != "" {
		return r.OAuth2(PasswordFlow, "")
	}
	return r.OAuth2(ClientCredentials, "")
}

func (r *CredentialRegistry) all() []*ManagedCredential {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	credentials := make([]*ManagedCredential, 0, len(r.credentials))
	for _, credential := range r.credentials {
		credentials = append(credentials, credential)
	}
	return credentials
}
