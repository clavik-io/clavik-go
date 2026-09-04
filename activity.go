package vault

import (
	"context"
	"net/http"
	"net/url"
)

// ActivityService provides methods for querying the audit trail.
type ActivityService struct {
	client *Client
}

// List returns activity logs with optional filtering and pagination.
func (s *ActivityService) List(ctx context.Context, opts ListActivityOptions) (*ListResponse[ActivityLog], error) {
	params := url.Values{}
	addQueryParam(params, "user_id", opts.UserID)
	addQueryParam(params, "action", opts.Action)
	addQueryParam(params, "resource_type", opts.ResourceType)
	addQueryParam(params, "resource_id", opts.ResourceID)
	addQueryParamEnum(params, "status", opts.Status)
	addQueryParam(params, "start_time", opts.StartTime)
	addQueryParam(params, "end_time", opts.EndTime)
	addQueryParamInt32(params, "skip", opts.Skip)
	addQueryParamInt32(params, "limit", opts.Limit)

	var resp ListResponse[ActivityLog]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "activity", "logs"), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Get retrieves a single activity log entry by ID.
func (s *ActivityService) Get(ctx context.Context, id string) (*ActivityLog, error) {
	var log ActivityLog
	if err := s.client.do(ctx, http.MethodGet, buildPath("activity", "logs", id), nil, &log); err != nil {
		return nil, err
	}
	return &log, nil
}
