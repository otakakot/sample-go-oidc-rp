package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/otakakot/sample-go-oidc-rp/pkg/api"
)

func main() {
	cid := os.Getenv("CLIENT_ID")

	cs := os.Getenv("CLIENT_SECRET")

	iss := os.Getenv("ISSUER")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	redirectURI := fmt.Sprintf("http://localhost:%s/callback", port)

	scope := []string{oidc.ScopeOpenID}

	prov, err := oidc.NewProvider(context.Background(), iss)
	if err != nil {
		panic(err)
	}

	hdl, err := api.NewServer(&Handler{
		authURI: fmt.Sprintf("http://localhost:%s/auth", port),
		config: &oauth2.Config{
			ClientID:     cid,
			ClientSecret: cs,
			Endpoint:     prov.Endpoint(),
			RedirectURL:  redirectURI,
			Scopes:       scope,
		},
		provider: prov,
	})
	if err != nil {
		panic(err)
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           hdl,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")
}

var _ api.Handler = (*Handler)(nil)

type Handler struct {
	authURI  string
	config   *oauth2.Config
	provider *oidc.Provider
}

// Get implements api.Handler.
func (hdl *Handler) Get(ctx context.Context) (api.GetOK, error) {
	loginTmpl, _ := template.New("login").Parse(view)

	data := &struct {
		URI string
	}{
		URI: hdl.authURI,
	}

	buf := new(bytes.Buffer)

	if err := loginTmpl.Execute(buf, data); err != nil {
		return api.GetOK{}, fmt.Errorf("failed to execute template: %w", err)
	}

	return api.GetOK{
		Data: buf,
	}, nil
}

const view = `
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <script>
        function onLoginButtonClick() {
            navigation.navigate(encodeURI("{{.URI}}"));
        }
    </script>
</head>
<body>
    <button onclick="onLoginButtonClick()">coreos</button>
</body>
</html>
`

// Auth implements api.Handler.
func (hdl *Handler) Auth(ctx context.Context) (api.AuthRes, error) {
	state := uuid.NewString()

	endpoint := hdl.config.AuthCodeURL(state)

	location, err := url.Parse(endpoint)
	if err != nil {
		return &api.ErrorResponse{
			Message: err.Error(),
		}, nil
	}

	cookie := &http.Cookie{
		Name:  "state",
		Value: state,
	}

	return &api.AuthFound{
		Location:  api.NewOptURI(*location),
		SetCookie: cookie.String(),
	}, nil
}

// Callback implements api.Handler.
func (hdl *Handler) Callback(ctx context.Context, params api.CallbackParams) (api.CallbackRes, error) {
	cookie := &http.Cookie{
		Name:   "state",
		Value:  "",
		MaxAge: -1,
	}

	if params.QueryState != params.CookieState {
		return &api.ErrorResponseHeaders{
			SetCookie: cookie.String(),
			Response: api.ErrorResponse{
				Message: "state mismatch",
			},
		}, nil
	}

	token, err := hdl.config.Exchange(ctx, params.Code)
	if err != nil {
		return &api.ErrorResponseHeaders{
			SetCookie: cookie.String(),
			Response: api.ErrorResponse{
				Message: err.Error(),
			},
		}, nil
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return &api.ErrorResponseHeaders{
			SetCookie: cookie.String(),
			Response: api.ErrorResponse{
				Message: "id_token not found",
			},
		}, nil
	}

	if _, err := hdl.provider.Verifier(&oidc.Config{
		ClientID: hdl.config.ClientID,
	}).Verify(ctx, idToken); err != nil {
		return &api.ErrorResponseHeaders{
			SetCookie: cookie.String(),
			Response: api.ErrorResponse{
				Message: err.Error(),
			},
		}, nil
	}

	return &api.CallbackResponseSchemaHeaders{
		SetCookie: cookie.String(),
		Response: api.CallbackResponseSchema{
			IDToken: idToken,
		},
	}, nil
}
