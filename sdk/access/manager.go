package access

import (
	"context"
	"net/http"
	"sync/atomic"
)

// Manager coordinates authentication providers.
// Uses atomic.Value for lock-free reads on the hot authentication path.
type Manager struct {
	providers atomic.Value // stores []Provider
}

// NewManager constructs an empty manager.
func NewManager() *Manager {
	m := &Manager{}
	m.providers.Store([]Provider(nil))
	return m
}

// SetProviders replaces the active provider list.
func (m *Manager) SetProviders(providers []Provider) {
	if m == nil {
		return
	}
	cloned := make([]Provider, len(providers))
	copy(cloned, providers)
	m.providers.Store(cloned)
}

// Providers returns the active providers.
// The returned slice must not be modified by callers.
func (m *Manager) Providers() []Provider {
	if m == nil {
		return nil
	}
	p, _ := m.providers.Load().([]Provider)
	return p
}

// Authenticate evaluates providers until one succeeds.
func (m *Manager) Authenticate(ctx context.Context, r *http.Request) (*Result, *AuthError) {
	if m == nil {
		return nil, nil
	}
	providers := m.Providers()
	if len(providers) == 0 {
		return nil, nil
	}

	var (
		missing bool
		invalid bool
	)

	for _, provider := range providers {
		if provider == nil {
			continue
		}
		res, authErr := provider.Authenticate(ctx, r)
		if authErr == nil {
			return res, nil
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeNotHandled) {
			continue
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeNoCredentials) {
			missing = true
			continue
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeInvalidCredential) {
			invalid = true
			continue
		}
		return nil, authErr
	}

	if invalid {
		return nil, NewInvalidCredentialError()
	}
	if missing {
		return nil, NewNoCredentialsError()
	}
	return nil, NewNoCredentialsError()
}
