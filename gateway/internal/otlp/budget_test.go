package otlp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
)

func TestCanonicalPrivateAttributeNamesAreScrubbedWithoutChangingProtocolIDs(t *testing.T) {
	keys := []string{"passcode", "bearer", "csrf", "session", "pin", "credit_limit", "card_number", "cvv", "pan", "iban", "e-mail", "telephone", "mobile", "dob", "birth_date", "ssn", "passport"}
	attributes := []any{}
	for _, key := range keys {
		attributes = append(attributes, map[string]any{"key": key, "value": map[string]any{"stringValue": "private-" + key}})
	}
	input := map[string]any{"spanId": "0102030405060708", "parentSpanId": "1112131415161718", "attributes": attributes}
	scrub(input)
	for _, item := range attributes {
		if asMap(asMap(item)["value"])["stringValue"] != "[Filtered]" {
			t.Fatalf("Canonical sensitive attribute was not filtered: %s", asMap(item)["key"])
		}
	}
	if input["spanId"] != "0102030405060708" || input["parentSpanId"] != "1112131415161718" {
		t.Fatal("Protocol identity fields must not be treated as semantic attributes")
	}
}

func TestAttributeKeyRedactionCollisionsRejectInsteadOfChangingIdentity(t *testing.T) {
	attributes := []any{
		map[string]any{"key": "first@example.test", "value": map[string]any{"stringValue": "one"}},
		map[string]any{"key": "second@example.test", "value": map[string]any{"stringValue": "two"}},
	}
	if validAttributes(attributes) || validDepth(map[string]any{"kvlistValue": map[string]any{"values": attributes}}, 0) {
		t.Fatal("Attribute keys colliding after privacy filtering must reject the affected item")
	}
	opaque := []any{
		map[string]any{"key": "test-project-a", "value": map[string]any{"stringValue": "one"}},
		map[string]any{"key": "[Filtered]", "value": map[string]any{"stringValue": "two"}},
	}
	if validAttributesWithCredential(opaque, "test-project-a") || validDepthWithCredential(map[string]any{"kvlistValue": map[string]any{"values": opaque}}, 0, "test-project-a") {
		t.Fatal("Actual opaque credential filtering must not introduce duplicate attribute keys")
	}
}

func TestSensitiveAttributeKeysAreSanitizedBeforeTheirValuesAreRedacted(t *testing.T) {
	token := "cyi_" + strings.Repeat("b", 40)
	for _, key := range []string{"email=private@example.test", "password: " + token} {
		attribute := map[string]any{"key": key, "value": map[string]any{"stringValue": "private value"}}
		scrub(attribute)
		filtered := attribute["key"].(string)
		if filtered != filteredAttributeKey(key, "") || strings.Contains(filtered, token) || strings.Contains(filtered, "private@example.test") {
			t.Fatal("Sensitive attribute key bypassed the privacy filter")
		}
	}
}

func TestUTF8AnyValueBytesAreScrubbedAndOpaqueBytesAreRejected(t *testing.T) {
	opaqueCredential := "test-project-a"
	value := map[string]any{"bytesValue": base64.StdEncoding.EncodeToString([]byte("request failed: " + opaqueCredential + " private@example.test"))}
	if !validDepth(value, 0) {
		t.Fatal("UTF-8 AnyValue bytes must remain supported")
	}
	scrub(value)
	scrubCredential(value, opaqueCredential)
	decoded, err := base64.StdEncoding.DecodeString(value["bytesValue"].(string))
	if err != nil || strings.Contains(string(decoded), opaqueCredential) || strings.Contains(string(decoded), "private@example.test") || !strings.Contains(string(decoded), "request failed:") {
		t.Fatal("UTF-8 byte value leaked private text or lost its non-private content")
	}
	plain := map[string]any{"bytesValue": base64.StdEncoding.EncodeToString([]byte("safe UTF-8 λ"))}
	before := plain["bytesValue"]
	scrub(plain)
	scrubCredential(plain, opaqueCredential)
	if plain["bytesValue"] != before {
		t.Fatal("Non-sensitive UTF-8 bytes changed")
	}
	for _, encoded := range []string{base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe}), "not valid base64!"} {
		if validDepth(map[string]any{"arrayValue": map[string]any{"values": []any{map[string]any{"bytesValue": encoded}}}}, 0) {
			t.Fatal("Opaque or malformed nested byte values must reject the affected item")
		}
	}
}

func TestBytePrivacyIsEnforcedBeforeEncryptedDurableAdmission(t *testing.T) {
	h := newHarness(t)
	privateBytes := base64.StdEncoding.EncodeToString([]byte("request failed: test-project-a private@example.test"))
	opaqueBytes := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0xfd})
	body := map[string]any{"resourceLogs": []any{map[string]any{"scopeLogs": []any{map[string]any{"logRecords": []any{
		map[string]any{"body": map[string]any{"bytesValue": privateBytes}, "attributes": []any{map[string]any{"key": "card_number", "value": map[string]any{"stringValue": "private-card-value"}}}},
		map[string]any{"body": map[string]any{"bytesValue": opaqueBytes}},
	}}}}}}
	encoded, _ := json.Marshal(body)
	code, response := h.post(t, "logs", encoded, "application/json", "", "Bearer test-project-a")
	var result map[string]any
	if code != 200 || json.Unmarshal(response, &result) != nil || asMap(result["partialSuccess"])["rejectedLogRecords"] != "1" {
		t.Fatal("Opaque byte record was not rejected with a partial-success count")
	}
	stored := h.next(t)
	for _, private := range []string{privateBytes, opaqueBytes, "test-project-a", "private@example.test", "private-card-value"} {
		if bytes.Contains(stored.Body, []byte(private)) {
			t.Fatal("Original private or opaque value survived before queue delivery")
		}
	}
	var persisted map[string]any
	if json.Unmarshal(stored.Body, &persisted) != nil || countSignal("logs", persisted) != 1 {
		t.Fatal("Valid UTF-8 record was not durably preserved")
	}
}

func TestScrubbingRemovesRawCredentialsAndURLUserinfoBeforeEmailMatching(t *testing.T) {
	token := "cyi_" + strings.Repeat("a", 40)
	for _, raw := range []string{"request failed: " + token, "https://unique-user:private-password@example.org/path?q=secret", "visit https://unique-user:private-password@example.org/path?q=secret now"} {
		filtered := scrubString(raw)
		for _, secret := range []string{token, "unique-user", "private-password", "q=secret"} {
			if strings.Contains(filtered, secret) {
				t.Fatalf("Sensitive value survived filtering: %s", secret)
			}
		}
	}
	value := map[string]any{"key": "url.full", "value": map[string]any{"stringValue": "https://unique-user:private-password@example.org/path?q=secret"}}
	scrub(value)
	filtered := asMap(value["value"])["stringValue"].(string)
	parsed, err := url.Parse(filtered)
	if err != nil || parsed.User != nil || parsed.Host != "example.org" || parsed.Query().Get("q") != "[Filtered]" {
		t.Fatalf("Filtered URL lost structure or kept userinfo: %q", filtered)
	}
}

func TestActualBearerIsScrubbedFromDurablePayloadEvenWithOpaqueFormat(t *testing.T) {
	h := newHarness(t)
	code, response := h.post(t, "logs", []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"request failed: test-project-a"}}]}]}]}`), "application/json", "", "Bearer test-project-a")
	if code != 200 {
		t.Fatalf("status=%d body=%s", code, response)
	}
	stored := h.next(t)
	if strings.Contains(string(stored.Body), "test-project-a") {
		t.Fatal("Authenticated bearer leaked into telemetry payload")
	}
	if stored.Headers["Authorization"] != "Bearer test-project-a" {
		t.Fatal("Encrypted delivery credential must remain available for reauthentication")
	}
}

func TestAttributeBudgetsAtBoundaries(t *testing.T) {
	attrs := []any{}
	for i := range 128 {
		attrs = append(attrs, map[string]any{"key": fmt.Sprintf("key%d", i), "value": map[string]any{"stringValue": "value"}})
	}
	if !validAttributes(attrs) {
		t.Fatal("Exactly 128 keys must fit")
	}
	if validAttributes(append(attrs, map[string]any{"key": "overflow"})) {
		t.Fatal("129 keys must be rejected")
	}
	for _, length := range []int{256, 257} {
		a := []any{map[string]any{"key": strings.Repeat("k", length), "value": map[string]any{"stringValue": "v"}}}
		if validAttributes(a) != (length == 256) {
			t.Fatalf("Incorrect key byte limit at %d", length)
		}
	}
	value := any(map[string]any{"stringValue": "leaf"})
	for range 8 {
		value = map[string]any{"arrayValue": map[string]any{"values": []any{value}}}
	}
	if !validDepth(value, 0) {
		t.Fatal("Depth 8 must fit")
	}
	value = map[string]any{"arrayValue": map[string]any{"values": []any{value}}}
	if validDepth(value, 0) {
		t.Fatal("Depth 9 must be rejected")
	}
	if validAttributes([]any{map[string]any{"key": "large", "value": map[string]any{"stringValue": strings.Repeat("v", 64*1024)}}}) {
		t.Fatal("Serialized attributes exceeding 64 KiB must be rejected")
	}
}

func TestPrivateAttributesAndFreeTextAreScrubbed(t *testing.T) {
	input := map[string]any{"attributes": []any{map[string]any{"key": "db.statement", "value": map[string]any{"stringValue": "select * from users where email='private@example.org'"}}, map[string]any{"key": "url.full", "value": map[string]any{"stringValue": "https://user:password@example.org/a?q=private"}}}, "body": map[string]any{"stringValue": "private@example.org password=hunter2 Bearer abc123 https://site.test/?query=secret"}}
	scrub(input)
	encoded, _ := json.Marshal(input)
	for _, secret := range []string{"private@example.org", "hunter2", "abc123", "user:password", "q=private", "query=secret", "select *"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("Sensitive value survived: %s", secret)
		}
	}
}

func TestMetricTypesPreserveSemanticsAndRejectSummary(t *testing.T) {
	h := newHarness(t)
	request := pmetricotlp.NewExportRequest()
	metrics := request.Metrics().ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics()
	metric := metrics.AppendEmpty()
	metric.SetName("requests")
	sum := metric.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.DataPoints().AppendEmpty().SetIntValue(9007199254740993)
	metric = metrics.AppendEmpty()
	metric.SetName("latency")
	hist := metric.SetEmptyHistogram().DataPoints().AppendEmpty()
	hist.SetCount(2)
	hist.SetSum(12)
	hist.ExplicitBounds().FromRaw([]float64{10})
	hist.BucketCounts().FromRaw([]uint64{1, 1})
	metric = metrics.AppendEmpty()
	metric.SetName("exponential")
	exp := metric.SetEmptyExponentialHistogram().DataPoints().AppendEmpty()
	exp.SetCount(1)
	exp.SetScale(2)
	exp.Positive().BucketCounts().FromRaw([]uint64{1})
	metric = metrics.AppendEmpty()
	metric.SetName("summary")
	metric.SetEmptySummary().DataPoints().AppendEmpty().SetCount(1)
	body, _ := request.MarshalJSON()
	code, response := h.post(t, "metrics", body, "application/json", "", "Bearer test-project-a")
	if code != 200 {
		t.Fatalf("status=%d body=%s", code, response)
	}
	result := pmetricotlp.NewExportResponse()
	if err := result.UnmarshalJSON(response); err != nil {
		t.Fatal(err)
	}
	if result.PartialSuccess().RejectedDataPoints() != 1 {
		t.Fatal("Summary was not rejected explicitly")
	}
	stored := h.next(t)
	received := pmetricotlp.NewExportRequest()
	if err := received.UnmarshalJSON(stored.Body); err != nil {
		t.Fatal(err)
	}
	kept := received.Metrics().ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	if kept.Len() != 3 || kept.At(0).Sum().DataPoints().At(0).IntValue() != 9007199254740993 || !kept.At(0).Sum().IsMonotonic() || kept.At(1).Histogram().DataPoints().At(0).BucketCounts().At(1) != 1 || kept.At(2).ExponentialHistogram().DataPoints().At(0).Scale() != 2 {
		t.Fatal("Metric normalization lost type, precision or histogram semantics")
	}
}
