package vault

import (
	"context"
	"net/http"
	"net/url"
)

// AlgorithmsService provides methods for querying supported cryptographic algorithms.
type AlgorithmsService struct {
	client *Client
}

// ListSupported returns supported algorithms, optionally filtered by key type.
func (s *AlgorithmsService) ListSupported(ctx context.Context, opts ListAlgorithmsOptions) ([]AlgorithmInfo, error) {
	params := url.Values{}
	addQueryParamEnum(params, "key_type", opts.KeyType)

	var resp dataListResponse[AlgorithmInfo]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "algorithms", "supported"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// GetRecommended returns the recommended algorithm for the given security requirements.
func (s *AlgorithmsService) GetRecommended(ctx context.Context, opts RecommendedOptions) (*AlgorithmInfo, error) {
	params := url.Values{}
	addQueryParamEnum(params, "key_type", opts.KeyType)
	addQueryParamEnum(params, "security_level", opts.SecurityLevel)
	addQueryParam(params, "compliance_mode", opts.ComplianceMode)

	var info AlgorithmInfo
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "algorithms", "recommended"), nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}
