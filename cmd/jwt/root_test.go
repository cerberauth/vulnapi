package jwt_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/cerberauth/vulnapi/cmd/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runGenerate(t *testing.T, args ...string) string {
	t.Helper()

	stdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	cmd := jwt.NewJWTCmd()
	cmd.SetArgs(append([]string{"generate"}, args...))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	require.NoError(t, cmd.Execute())

	require.NoError(t, w.Close())
	var out bytes.Buffer
	_, err = io.Copy(&out, r)
	require.NoError(t, err)
	return out.String()
}

func TestGenerateDoesNotEchoSecretOrToken(t *testing.T) {
	out := runGenerate(t, "my-token", "--alg", "HS256", "--secret", "super-secret")

	assert.Contains(t, out, "jwtop sign <token> --alg HS256 --secret <secret>")
	assert.NotContains(t, out, "super-secret")
	assert.NotContains(t, out, "my-token")
}

func TestGenerateFallsBackToAlgPlaceholder(t *testing.T) {
	out := runGenerate(t, "my-token")

	assert.Contains(t, out, "--alg <alg>")
}
