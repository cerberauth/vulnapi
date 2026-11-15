package scan

import (
	"path"
	"slices"
	"strings"

	"github.com/cerberauth/vulnapi/internal/operation"
)

type OperationFilter struct {
	Paths        []string
	ExcludePaths []string
	Tags         []string
	OperationIDs []string
	Methods      []string
}

func operationPath(op *operation.Operation) string {
	if op.OpenAPIDocPath != nil {
		return *op.OpenAPIDocPath
	}
	if op.URL.Path == "" {
		return "/"
	}
	return op.URL.Path
}

func (f *OperationFilter) Match(op *operation.Operation) bool {
	if f == nil {
		return true
	}
	p := operationPath(op)
	if len(f.Paths) > 0 && !slices.ContainsFunc(f.Paths, func(pattern string) bool { return MatchPath(pattern, p) }) {
		return false
	}
	if slices.ContainsFunc(f.ExcludePaths, func(pattern string) bool { return MatchPath(pattern, p) }) {
		return false
	}
	if len(f.Tags) > 0 && !slices.ContainsFunc(op.Tags, func(tag string) bool { return slices.Contains(f.Tags, tag) }) {
		return false
	}
	if len(f.OperationIDs) > 0 && !slices.Contains(f.OperationIDs, op.GetID()) {
		return false
	}
	if len(f.Methods) > 0 && !slices.ContainsFunc(f.Methods, func(method string) bool { return strings.EqualFold(method, op.Method) }) {
		return false
	}
	return true
}

func (f *OperationFilter) Filter(operations operation.Operations) operation.Operations {
	var filtered operation.Operations
	for _, op := range operations {
		if f.Match(op) {
			filtered = append(filtered, op)
		}
	}
	return filtered
}

// MatchPath matches an operation path against a pattern where "*" matches
// one path segment, or part of it, and "**" any number of segments.
func MatchPath(pattern, p string) bool {
	return matchSegments(strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(p, "/"), "/"))
}

func matchSegments(pattern, segments []string) bool {
	if len(pattern) == 0 {
		return len(segments) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(segments); i++ {
			if matchSegments(pattern[1:], segments[i:]) {
				return true
			}
		}
		return false
	}
	if len(segments) == 0 {
		return false
	}
	if ok, _ := path.Match(pattern[0], segments[0]); !ok {
		return false
	}
	return matchSegments(pattern[1:], segments[1:])
}
