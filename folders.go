package vault

import (
	"context"
	"net/http"
	"net/url"
)

// FoldersService provides methods for managing folders and folder permissions.
type FoldersService struct {
	client *Client
}

// Create creates a new folder.
func (s *FoldersService) Create(ctx context.Context, req CreateFolderRequest) (*Folder, error) {
	var folder Folder
	if err := s.client.do(ctx, http.MethodPost, buildPath("folders"), req, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

// List returns folders, optionally filtered by parent or type.
func (s *FoldersService) List(ctx context.Context, opts ListFoldersOptions) ([]Folder, error) {
	params := url.Values{}
	addQueryParam(params, "parent_id", opts.ParentID)
	addQueryParamEnum(params, "folder_type", opts.FolderType)

	var resp dataListResponse[Folder]
	if err := s.client.do(ctx, http.MethodGet, buildPathWithQuery(params, "folders"), nil, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// Get retrieves a folder by ID.
func (s *FoldersService) Get(ctx context.Context, id string) (*Folder, error) {
	var folder Folder
	if err := s.client.do(ctx, http.MethodGet, buildPath("folders", id), nil, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

// Update updates a folder's name, parent, or type.
func (s *FoldersService) Update(ctx context.Context, id string, req UpdateFolderRequest) (*Folder, error) {
	var folder Folder
	if err := s.client.do(ctx, http.MethodPut, buildPath("folders", id), req, &folder); err != nil {
		return nil, err
	}
	return &folder, nil
}

// Delete deletes a folder.
func (s *FoldersService) Delete(ctx context.Context, id string) error {
	return s.client.do(ctx, http.MethodDelete, buildPath("folders", id), nil, nil)
}

// ListPermissions returns the role grants on a folder.
func (s *FoldersService) ListPermissions(ctx context.Context, folderID string) ([]FolderPermission, error) {
	var perms []FolderPermission
	if err := s.client.do(ctx, http.MethodGet, buildPath("folders", folderID, "permissions"), nil, &perms); err != nil {
		return nil, err
	}
	return perms, nil
}

// GrantPermission grants or updates a user's roles on a folder.
// The API returns all permissions on the folder after the grant.
func (s *FoldersService) GrantPermission(ctx context.Context, folderID string, req GrantPermissionRequest) ([]FolderPermission, error) {
	var resp dataListResponse[FolderPermission]
	if err := s.client.do(ctx, http.MethodPut, buildPath("folders", folderID, "permissions"), req, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// RemovePermission removes a user's access to a folder.
func (s *FoldersService) RemovePermission(ctx context.Context, folderID, userID string) error {
	params := url.Values{}
	params.Set("user_id", userID)
	return s.client.do(ctx, http.MethodDelete, buildPathWithQuery(params, "folders", folderID, "permissions"), nil, nil)
}
