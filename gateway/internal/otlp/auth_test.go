package otlp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthorizationDependencyFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name string
		code int
		body string
		want codes.Code
	}{
		{"invalid-credential", 401, `{}`, codes.Unauthenticated},
		{"forbidden", 403, `{}`, codes.PermissionDenied},
		{"dependency-down", 503, `{}`, codes.Unavailable},
		{"malformed", 200, `{`, codes.Unavailable},
		{"missing-organization", 200, fmt.Sprintf(`{"data":{"project_id":%q}}`, testProjectA), codes.Unavailable},
		{"path-injection", 200, fmt.Sprintf(`{"data":{"project_id":"../other","organization_id":%q}}`, testOrganization), codes.Unavailable},
		{"response-limit", 200, strings.Repeat("x", 16*1024+1), codes.Unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(test.code); fmt.Fprint(w, test.body) }))
			defer backend.Close()
			u, _ := url.Parse(backend.URL)
			_, err := (RemoteAuthorizer{Upstream: u, Client: backend.Client()}).Authorize(context.Background(), "Bearer transient-test-credential")
			if status.Code(err) != test.want {
				t.Fatalf("status=%v want=%v", status.Code(err), test.want)
			}
			if strings.Contains(err.Error(), "transient-test-credential") {
				t.Fatal("Credential leaked in diagnostic")
			}
		})
	}
}
