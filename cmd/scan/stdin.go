package scan

import (
	"errors"
	"io"
	"os"
	"strings"
)

// maxStdinTokenSize bounds how much of stdin is read as a token.
const maxStdinTokenSize = 64 * 1024

func isStdinOpen() bool {
	stat, err := os.Stdin.Stat()
	if err != nil || stat == nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// readToken reads a token from r until EOF and trims surrounding whitespace,
// including the trailing newline added by echo.
func readToken(r io.Reader) (*string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxStdinTokenSize))
	if err != nil {
		return nil, err
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return nil, errors.New("no token found on stdin")
	}
	return &token, nil
}
