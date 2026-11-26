package mcpserver_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/mcpserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvResolverResolve(t *testing.T) {
	t.Setenv("VULNAPI_TEST_TOKEN", "Bearer abc")
	t.Setenv("MY_API_TOKEN", "value-2")
	t.Setenv("OTHER_SECRET", "hidden")
	t.Setenv("APP_KEY_ONE", "value-3")
	t.Setenv("VULNAPI_EMPTY", "")

	resolver := mcpserver.NewEnvResolver([]string{"MY_API_TOKEN", "APP_KEY_*"})

	tests := []struct {
		name    string
		want    string
		wantErr string
	}{
		{name: "VULNAPI_TEST_TOKEN", want: "Bearer abc"},
		{name: "MY_API_TOKEN", want: "value-2"},
		{name: "APP_KEY_ONE", want: "value-3"},
		{name: "OTHER_SECRET", wantErr: "not available to tool calls"},
		{name: "VULNAPI_NOT_SET", wantErr: "is not set"},
		{name: "VULNAPI_EMPTY", wantErr: "is not set"},
		{name: "Bearer eyJhbGciOi.payload.sig", wantErr: "never the credential itself"},
		{name: "", wantErr: "never the credential itself"},
		{name: "1BAD", wantErr: "never the credential itself"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolver.Resolve(tt.name)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEnvResolverErrorDoesNotLeakValue(t *testing.T) {
	t.Setenv("OTHER_SECRET", "super-secret-value")
	_, err := mcpserver.NewEnvResolver(nil).Resolve("OTHER_SECRET")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "super-secret-value")
}
