package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrUnauthorized = errors.New("vault: unauthorized")
	ErrForbidden    = errors.New("vault: forbidden")
	ErrNotFound     = errors.New("vault: not found")
	ErrValidation   = errors.New("vault: validation error")
	ErrServerError  = errors.New("vault: server error")
)

// APIError represents an error response from the Clavik API.
type APIError struct {
	StatusCode int
	Message    string
	Details    json.RawMessage
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("vault: API error %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("vault: API error %d", e.StatusCode)
}

func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusBadRequest:
		return ErrValidation
	default:
		if e.StatusCode >= http.StatusInternalServerError {
			return ErrServerError
		}
		return nil
	}
}

// IsAPIError reports whether err is an *APIError with the given status code.
func IsAPIError(err error, statusCode int) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == statusCode
	}
	return false
}
