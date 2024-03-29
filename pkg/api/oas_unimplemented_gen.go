// Code generated by ogen, DO NOT EDIT.

package api

import (
	"context"

	ht "github.com/ogen-go/ogen/http"
)

// UnimplementedHandler is no-op Handler which returns http.ErrNotImplemented.
type UnimplementedHandler struct{}

var _ Handler = UnimplementedHandler{}

// Auth implements auth operation.
//
// OIDC Authorization.
//
// GET /auth
func (UnimplementedHandler) Auth(ctx context.Context) (r AuthRes, _ error) {
	return r, ht.ErrNotImplemented
}

// Callback implements callback operation.
//
// OIDC Callback.
//
// GET /callback
func (UnimplementedHandler) Callback(ctx context.Context, params CallbackParams) (r CallbackRes, _ error) {
	return r, ht.ErrNotImplemented
}

// Get implements GET / operation.
//
// Login.
//
// GET /
func (UnimplementedHandler) Get(ctx context.Context) (r GetOK, _ error) {
	return r, ht.ErrNotImplemented
}
