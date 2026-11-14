package telemetry_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// declaration matches argvio.NewCounter("name", argvio.Dims("dim", ...)),
// NewDuration("name", ...) and NewValue("name", ...); dims takes the quoted
// dimension names out of the argvio.Dims(...) part.
var declaration = regexp.MustCompile(`argvio\.New(Counter|Duration|Value)\(\s*"([^"]+)"([^\n]*)`)
var dimsList = regexp.MustCompile(`argvio\.Dims\(([^)]*)\)`)
var quoted = regexp.MustCompile(`"([^"]+)"`)

// catalogEnv names the vulnapi catalog file to check the code against. The
// catalog is not in this repository, so the test only runs when pointed at a
// copy of it:
//
//	ARGVIO_METRICS_CATALOG=/path/to/vulnapi.yaml go test ./internal/telemetry
const catalogEnv = "ARGVIO_METRICS_CATALOG"

// A metric whose name or dimensions differ between the code and the catalog
// is dropped by Argvio without any error, so check that they agree.
// scanmetrics' metrics are declared in x, not here.
func TestMetricDeclarationsMatchCatalog(t *testing.T) {
	catalogPath := os.Getenv(catalogEnv)
	if catalogPath == "" {
		t.Skipf("set %s to the vulnapi catalog to check the declared metrics against it", catalogEnv)
	}
	root := filepath.Join("..", "..")

	raw, err := os.ReadFile(catalogPath)
	require.NoError(t, err)
	var catalog struct {
		Metrics []struct {
			Name string   `yaml:"name"`
			Kind string   `yaml:"kind"`
			Dims []string `yaml:"dims"`
		} `yaml:"metrics"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &catalog))
	type entry struct{ kind, dims string }
	inCatalog := map[string]entry{}
	for _, m := range catalog.Metrics {
		inCatalog[m.Name] = entry{m.Kind, strings.Join(m.Dims, ",")}
	}

	inCode := map[string]entry{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range declaration.FindAllStringSubmatch(string(src), -1) {
			kind, name, rest := strings.ToLower(m[1]), m[2], m[3]
			var dims []string
			if d := dimsList.FindStringSubmatch(rest); d != nil {
				for _, q := range quoted.FindAllStringSubmatch(d[1], -1) {
					dims = append(dims, q[1])
				}
			}
			inCode[name] = entry{kind, strings.Join(dims, ",")}
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, inCode)

	names := make([]string, 0, len(inCode))
	for name := range inCode {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		want, ok := inCatalog[name]
		if assert.True(t, ok, "%s is declared in code but not in the catalog", name) {
			assert.Equal(t, want, inCode[name], "%s: kind or dimensions differ from the catalog", name)
		}
	}
}
