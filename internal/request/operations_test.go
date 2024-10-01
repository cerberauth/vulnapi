package request_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestOperations_Less(t *testing.T) {
	getOperation, _ := request.NewOperation(http.MethodGet, "http://example.com", nil, nil)
	postOperation, _ := request.NewOperation(http.MethodPost, "http://example.com", nil, nil)

	tests := []struct {
		name     string
		ops      request.Operations
		i, j     int
		expected bool
	}{
		{
			name: "Different URLs",
			ops: request.Operations{
				getOperation,
				postOperation,
			},
			i:        0,
			j:        1,
			expected: true,
		},
		{
			name: "Same URLs, different methods",
			ops: request.Operations{
				postOperation,
				getOperation,
			},
			i:        0,
			j:        1,
			expected: false,
		},
		{
			name: "Same URLs and methods",
			ops: request.Operations{
				getOperation,
				getOperation,
			},
			i:        0,
			j:        1,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ops.Less(tt.i, tt.j)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOperations_GetByID(t *testing.T) {
	getOperation, _ := request.NewOperation(http.MethodGet, "http://example.com", nil, nil)
	getOperation.SetID("1")
	postOperation, _ := request.NewOperation(http.MethodPost, "http://example.com", nil, nil)
	postOperation.SetID("2")

	tests := []struct {
		name     string
		ops      request.Operations
		id       string
		expected *request.Operation
	}{
		{
			name: "Existing ID",
			ops: request.Operations{
				getOperation,
				postOperation,
			},
			id:       "1",
			expected: getOperation,
		},
		{
			name: "Non-existing ID",
			ops: request.Operations{
				getOperation,
				postOperation,
			},
			id:       "3",
			expected: nil,
		},
		{
			name: "Empty ID",
			ops: request.Operations{
				getOperation,
				postOperation,
			},
			id:       "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.ops.GetByID(tt.id)
			assert.Equal(t, tt.expected, result)
		})
	}
}
