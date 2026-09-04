package vault

import (
	"context"
	"encoding/json"
	"net/http"
)

// ComplianceService provides compliance reports.
type ComplianceService struct {
	client *Client
}

// GetReport returns the consolidated compliance report for the account.
func (s *ComplianceService) GetReport(ctx context.Context) (json.RawMessage, error) {
	var report json.RawMessage
	if err := s.client.do(ctx, http.MethodGet, buildPath("compliance", "report"), nil, &report); err != nil {
		return nil, err
	}
	return report, nil
}
