package report_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewVulnerabilityReport(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	assert.Equal(t, "id", vr.ID)
	assert.Equal(t, "Test Vulnerability", vr.Name)
	assert.Equal(t, "http://test.com", vr.URL)
	assert.Equal(t, 7.5, vr.CVSS.Score)
}

func TestVulnerabilityReport_WithOperation(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	operation, _ := request.NewOperation("GET", "/api/v1/", nil, nil)
	vr.WithOperation(operation)
	assert.Equal(t, "GET", vr.Operation.Method)
	assert.Equal(t, "/api/v1/", vr.Operation.URL.Path)
}

func TestVulnerabilityReport_WithSecurityScheme(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	value := jwt.FakeJWT
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &value)
	vr.WithSecurityScheme(securityScheme)
	assert.Equal(t, jwt.FakeJWT, vr.SecurityScheme.GetValidValue())
}

func TestVulnerabilityReport_WithStatus(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.WithStatus(report.VulnerabilityReportStatusFail)
	assert.Equal(t, report.VulnerabilityReportStatusFail, vr.Status)
}

func TestVulnerabilityReport_WithBooleanStatus_WhenFalse(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.WithBooleanStatus(false)
	assert.Equal(t, report.VulnerabilityReportStatusFail, vr.Status)
}

func TestVulnerabilityReport_WithBooleanStatus_WhenTrue(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.WithBooleanStatus(true)
	assert.Equal(t, report.VulnerabilityReportStatusPass, vr.Status)
}

func TestVulnerabilityReport_Fail(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.Fail()
	assert.Equal(t, report.VulnerabilityReportStatusFail, vr.Status)
}

func TestVulnerabilityReport_HasFailed(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.Fail()
	assert.True(t, vr.HasFailed())
}

func TestVulnerabilityReport_Pass(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.Pass()
	assert.Equal(t, report.VulnerabilityReportStatusPass, vr.Status)
}

func TestVulnerabilityReport_HasPassed(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.Pass()
	assert.True(t, vr.HasPassed())
}

func TestVulnerabilityReport_Skip(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.Skip()
	assert.Equal(t, report.VulnerabilityReportStatusSkip, vr.Status)
}

func TestVulnerabilityReport_HasBeenSkipped(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewVulnerabilityReport(issue)
	vr.Skip()
	assert.True(t, vr.HasBeenSkipped())
}

func TestVulnerabilityReport_IsInfoRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 0,
			},
		},
	}
	assert.True(t, vr.IsInfoRiskSeverity())
}

func TestVulnerabilityReport_IsLowRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 3.5,
			},
		},
	}
	assert.True(t, vr.IsLowRiskSeverity())
}

func TestVulnerabilityReport_IsMediumRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 5.5,
			},
		},
	}
	assert.True(t, vr.IsMediumRiskSeverity())
}

func TestVulnerabilityReport_IsHighRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 8.5,
			},
		},
	}
	assert.True(t, vr.IsHighRiskSeverity())
}

func TestVulnerabilityReport_IsCriticalRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 9.5,
			},
		},
	}
	assert.True(t, vr.IsCriticalRiskSeverity())
}

func TestVulnerabilityReport_String(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			Name: "Test Vulnerability",

			CVSS: report.CVSS{
				Score: 7.5,
			},
		},
	}
	expected := "[High] Test Vulnerability"
	assert.Equal(t, expected, vr.String())
}

func TestVulnerabilityReport_SeverityLevelString(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			CVSS: report.CVSS{},
		},
	}

	// Test case for severity level >= 9
	vr.Issue.CVSS.Score = 9.5
	assert.Equal(t, "Critical", vr.SeverityLevelString())

	// Test case for severity level < 9 and >= 7
	vr.Issue.CVSS.Score = 7.5
	assert.Equal(t, "High", vr.SeverityLevelString())

	// Test case for severity level < 7 and >= 4
	vr.Issue.CVSS.Score = 4.5
	assert.Equal(t, "Medium", vr.SeverityLevelString())

	// Test case for severity level < 4 and >= 0.1
	vr.Issue.CVSS.Score = 0.5
	assert.Equal(t, "Low", vr.SeverityLevelString())

	// Test case for severity level < 0.1
	vr.Issue.CVSS.Score = -1
	assert.Equal(t, "None", vr.SeverityLevelString())
}

func TestVulnerabilityReport_Clone(t *testing.T) {
	vr := &report.VulnerabilityReport{
		Issue: report.Issue{
			Name: "Test Vulnerability",
			URL:  "http://test.com",
			CVSS: report.CVSS{
				Score: 7.5,
			},
		},
	}
	clone := vr.Clone()
	assert.Equal(t, vr.ID, clone.ID)
	assert.Equal(t, vr.Name, clone.Name)
	assert.Equal(t, vr.URL, clone.URL)
	assert.Equal(t, vr.Issue.ID, clone.Issue.ID)
	assert.Equal(t, vr.Issue.Name, clone.Issue.Name)
	assert.Equal(t, vr.CVSS.Score, clone.CVSS.Score)
	assert.Equal(t, vr.Operation, clone.Operation)
	assert.Equal(t, vr.SecurityScheme, clone.SecurityScheme)
}
