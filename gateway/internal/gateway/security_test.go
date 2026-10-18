package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
)

func TestUnverifiedResponsesCannotOccupyTheQueue(t *testing.T) {
	for _, status := range []int{408, 425, 429, 500, 503} {
		upstream := response(status, "retry")
		upstream.Header.Del(AdmissionHeader)
		publisher := &fakePublisher{}
		handler, _ := newTestHandler(t, &fakeClient{response: upstream}, publisher)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/p/events", strings.NewReader("{}"))
		request.Header.Set(AdmissionHeader, "true")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != status || publisher.calls != 0 {
			t.Fatalf("status=%d publishes=%d", recorder.Code, publisher.calls)
		}
	}
}

func TestOriginSurvivesDirectAndDeferredDelivery(t *testing.T) {
	client := &fakeClient{response: response(http.StatusServiceUnavailable, "retry")}
	publisher := &fakePublisher{}
	handler, cryptor := newTestHandler(t, client, publisher)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/p/events", strings.NewReader("{}"))
	request.Header.Set("Origin", "https://browser.example")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if client.request.Header.Get("Origin") != "https://browser.example" {
		t.Fatal("direct Origin lost")
	}
	raw, err := cryptor.Decrypt(publisher.message.Ciphertext, []byte("events"))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := envelope.Decode(raw)
	if err != nil || stored.Headers["Origin"] != "https://browser.example" {
		t.Fatal("queued Origin lost")
	}
}

type unreadBody struct{ t *testing.T }

func (b unreadBody) Read([]byte) (int, error) {
	b.t.Fatal("body read before admission")
	return 0, io.EOF
}
func (unreadBody) Close() error { return nil }

func TestBufferReservationPrecedesReadingTheBody(t *testing.T) {
	publisher := &fakePublisher{}
	handler, _ := newTestHandler(t, &fakeClient{err: context.DeadlineExceeded}, publisher)
	for i := 0; i < MaxBufferedRequests; i++ {
		handler.bodySlots <- struct{}{}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/p/events", nil)
	request.Body = unreadBody{t}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || publisher.calls != 0 {
		t.Fatal("buffer budget ignored")
	}
}
