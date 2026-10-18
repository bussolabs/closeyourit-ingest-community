package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Principal struct {
	OrganizationID string `json:"organization_id"`
	ProjectID      string `json:"project_id"`
	Credential     string `json:"-"`
}

type Authorizer interface {
	Authorize(context.Context, string) (Principal, error)
}
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// RemoteAuthorizer fails closed on every authorization dependency failure. Never cache
// a successful decision: revocation must take effect before the next durable admission.
type RemoteAuthorizer struct {
	Upstream *url.URL
	Client   HTTPClient
}

var identifier = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (a RemoteAuthorizer) Authorize(ctx context.Context, credential string) (Principal, error) {
	if !strings.HasPrefix(credential, "Bearer ") || len(credential) > 4096 || strings.TrimSpace(strings.TrimPrefix(credential, "Bearer ")) == "" {
		return Principal{}, status.Error(codes.Unauthenticated, "A project bearer credential is required")
	}
	target := *a.Upstream
	target.Path, target.RawQuery = "/api/v1/otlp/authorizations", ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewBufferString("{}"))
	if err != nil {
		return Principal{}, status.Error(codes.Unavailable, "Authorization service is unavailable")
	}
	req.Header.Set("Authorization", credential)
	req.Header.Set("Content-Type", "application/json")
	response, err := a.Client.Do(req)
	if err != nil {
		return Principal{}, status.Error(codes.Unavailable, "Authorization service is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == 401 {
		return Principal{}, status.Error(codes.Unauthenticated, "Invalid project credential")
	}
	if response.StatusCode == 403 {
		return Principal{}, status.Error(codes.PermissionDenied, "Project ingest is not permitted")
	}
	if response.StatusCode != 200 {
		return Principal{}, status.Error(codes.Unavailable, "Authorization service is unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil || len(body) > 16*1024 {
		return Principal{}, status.Error(codes.Unavailable, "Invalid authorization response")
	}
	var result struct {
		Data Principal `json:"data"`
	}
	if json.Unmarshal(body, &result) != nil || !identifier.MatchString(result.Data.ProjectID) || !identifier.MatchString(result.Data.OrganizationID) {
		return Principal{}, status.Error(codes.Unavailable, "Invalid authorization response")
	}
	result.Data.Credential = credential
	return result.Data, nil
}

type principalKey struct{}

func withPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}
func principalFrom(ctx context.Context) (Principal, error) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	if !ok || p.Credential == "" || !identifier.MatchString(p.ProjectID) || !identifier.MatchString(p.OrganizationID) {
		return Principal{}, errors.New("Authenticated project context is required")
	}
	return p, nil
}
