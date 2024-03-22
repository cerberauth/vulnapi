package seclist_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/cerberauth/vulnapi/seclist"
	"github.com/stretchr/testify/assert"
)

func TestNewSecListFromFile(t *testing.T) {
	file := "line 1\nline 2\nline 3\n"
	f, err := os.CreateTemp("", "seclist")
	assert.NoError(t, err)
	defer os.Remove(f.Name())

	io.WriteString(f, file)

	seclist, err := seclist.NewSecListFromFile("seclist", f.Name())

	assert.NoError(t, err)
	assert.Equal(t, 3, len(seclist.Items))
	assert.Equal(t, "line 1", seclist.Items[0])
	assert.Equal(t, "line 2", seclist.Items[1])
	assert.Equal(t, "line 3", seclist.Items[2])
}

func TestNewSecListFromURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("line 1\n"))
		w.Write([]byte("line 2\n"))
		w.Write([]byte("line 3\n"))
	}))
	defer server.Close()

	seclist, err := seclist.NewSecListFromURL("seclist", server.URL)

	assert.NoError(t, err)
	assert.Equal(t, 3, len(seclist.Items))
	assert.Equal(t, "line 1", seclist.Items[0])
	assert.Equal(t, "line 2", seclist.Items[1])
	assert.Equal(t, "line 3", seclist.Items[2])
}

func TestNewSecListFromURLWhenResponseNotOk(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := seclist.NewSecListFromURL("seclist", server.URL)

	assert.Error(t, err)
}
