package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cerberauth/jwtop/jwt/editor"
)

const credentialExpiryLeeway = 30 * time.Second

const credentialFetchTimeout = 30 * time.Second

var ErrCredentialUnavailable = errors.New("credential unavailable")

type Credential struct {
	Value  string
	Expiry time.Time
}

func (c Credential) expired(now time.Time) bool {
	return !c.Expiry.IsZero() && now.Add(credentialExpiryLeeway).After(c.Expiry)
}

type CredentialSource interface {
	Credential(ctx context.Context) (Credential, error)
}

type CredentialSourceFunc func(ctx context.Context) (Credential, error)

func (f CredentialSourceFunc) Credential(ctx context.Context) (Credential, error) {
	return f(ctx)
}

type ManagedCredential struct {
	source  CredentialSource
	mu      sync.Mutex
	current Credential
	fetched bool
	now     func() time.Time
}

func NewManagedCredential(source CredentialSource) *ManagedCredential {
	return &ManagedCredential{source: source, now: time.Now}
}

func (m *ManagedCredential) fetch(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, credentialFetchTimeout)
	defer cancel()
	credential, err := m.source.Credential(ctx)
	if err != nil {
		return "", err
	}
	if credential.Value == "" {
		return "", ErrCredentialUnavailable
	}
	if credential.Expiry.IsZero() {
		credential.Expiry = jwtExpiry(credential.Value)
	}
	m.current = credential
	m.fetched = true
	return credential.Value, nil
}

func (m *ManagedCredential) Value(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fetched && !m.current.expired(m.now()) {
		return m.current.Value, nil
	}
	return m.fetch(ctx)
}

func (m *ManagedCredential) Refresh(ctx context.Context, stale string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fetched && m.current.Value != stale && !m.current.expired(m.now()) {
		return m.current.Value, nil
	}
	return m.fetch(ctx)
}

func (m *ManagedCredential) Current() (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current.Value, m.fetched
}

func jwtExpiry(value string) time.Time {
	te, err := editor.NewTokenEditor(value)
	if err != nil {
		return time.Time{}
	}
	exp, err := te.GetToken().Claims.GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}
	}
	return exp.Time
}
