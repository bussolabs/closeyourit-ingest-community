package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMinidumpNeverEntersDurableFallback(t *testing.T) {
	client := &fakeClient{response: response(http.StatusServiceUnavailable, `{"error":"retry"}`)}
	publisher := &fakePublisher{}
	handler, _ := newTestHandler(t, client, publisher)
	request := httptest.NewRequest(http.MethodPost, "https://ingest.example/api/1/minidump/?sentry_key=public", strings.NewReader("diagnostic bytes"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || publisher.calls != 0 {
		t.Fatalf("raw minidump was not fail-closed: status=%d queued=%d", recorder.Code, publisher.calls)
	}
}

func TestMinidumpHasSeparateBoundedAdmission(t *testing.T) {
	client := &fakeClient{response: response(http.StatusOK, `{"id":"event"}`)}
	handler, _ := newTestHandler(t, client, &fakePublisher{})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/1/minidump", strings.NewReader(strings.Repeat("x", int(DefaultMaxBodyBytes+1)))))
	if recorder.Code != http.StatusOK {
		t.Fatalf("dedicated native body limit not applied: %d", recorder.Code)
	}
	handler.nativeSlots <- struct{}{}
	handler.nativeSlots <- struct{}{}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/1/minidump", strings.NewReader("small")))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("native concurrency cap not applied: %d", recorder.Code)
	}
}

func TestSentryEnvelopesNeverEnterDurableFallback(t *testing.T) {
	gzipBody := func(body string) []byte {
		var out bytes.Buffer
		writer := gzip.NewWriter(&out)
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	ordinary := "{}\n{\"type\":\"event\"}\n{\"message\":\"ordinary\"}"
	ignored := ordinary + "\n{\"type\":\"unknown\",\"length\":4}\nMDMP"
	concatenated := append(gzipBody(ordinary), gzipBody("MDMP diagnostic bytes")...)
	for _, tc := range []struct {
		name        string
		body        []byte
		unavailable bool
	}{
		{"ordinary", []byte(ordinary), false},
		{"ignored binary item", []byte(ignored), false},
		{"concatenated gzip", concatenated, false},
		{"transport failure", []byte(ordinary), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := response(http.StatusServiceUnavailable, `{"error":"retry"}`)
			// Neither client nor upstream headers may authorize durable raw envelope storage.
			upstream.Header.Set("X-CloseYourIt-Attachment-Free", "true")
			upstream.Header.Set("X-CloseYourIt-Ingest-Authorized", "true")
			client := &fakeClient{response: upstream}
			if tc.unavailable {
				client.response = nil
				client.err = context.DeadlineExceeded
			}
			publisher := &fakePublisher{}
			handler, _ := newTestHandler(t, client, publisher)
			request := httptest.NewRequest(http.MethodPost, "/api/1/envelope/", bytes.NewReader(tc.body))
			request.Header.Set("X-CloseYourIt-Attachment-Free", "true")
			if tc.name == "concatenated gzip" {
				request.Header.Set("Content-Encoding", "gzip")
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusServiceUnavailable || publisher.calls != 0 {
				t.Fatalf("raw envelope entered queue: %d / %d", recorder.Code, publisher.calls)
			}
			if client.request.Header.Get("X-CloseYourIt-Attachment-Free") != "" {
				t.Fatal("client attachment attestation was forwarded upstream")
			}
		})
	}
}
