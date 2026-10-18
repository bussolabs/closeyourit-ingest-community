package tracecontext

import (
	"strings"
	"testing"
)

// validTraceparent is the W3C specification example: using it here makes it
// clear that the tests are not chasing a home-made format.
const validTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func TestValidTraceparentPassesUnchanged(t *testing.T) {
	if got := SanitizeTraceparent(validTraceparent); got != validTraceparent {
		t.Fatalf("traceparent = %q", got)
	}
}

func TestMalformedTraceparentIsDropped(t *testing.T) {
	cases := map[string]string{
		"empty":                    "",
		"too short":                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
		"wrong separators":         "00:4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:01",
		"trace id not hexadecimal": "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01",
		"trace id uppercase":       "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"trace id all zero":        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"span id all zero":         "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"version ff":               "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"version 00 with tail":     validTraceparent + "-extra",
		"tail without separator":   "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01extra",
		"with line break":          validTraceparent + "\r\nX-Injected: 1",
	}
	for name, value := range cases {
		if got := SanitizeTraceparent(value); got != "" {
			t.Fatalf("%s: traceparent kept = %q", name, got)
		}
	}
}

func TestFutureVersionTraceparentIsPropagatedWithItsTail(t *testing.T) {
	future := "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-campo-futuro"

	if got := SanitizeTraceparent(future); got != future {
		t.Fatalf("future version traceparent = %q", got)
	}
}

func TestValidTracestatePassesUnchanged(t *testing.T) {
	value := "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE"

	if got := SanitizeTracestate(value); got != value {
		t.Fatalf("tracestate = %q", got)
	}
}

func TestTracestateNormalizesSpacesAndIgnoresEmptyMembers(t *testing.T) {
	if got := SanitizeTracestate("rojo=1, ,  congo=2"); got != "rojo=1,congo=2" {
		t.Fatalf("tracestate = %q", got)
	}
}

func TestMalformedTracestateIsDroppedEntirely(t *testing.T) {
	cases := map[string]string{
		"member without equals sign":               "rojo=1,congo",
		"uppercase key":                            "Rojo=1",
		"key starting with a digit without tenant": "1rojo=1",
		"empty value":                              "rojo=",
		"duplicate key":                            "rojo=1,rojo=2",
		"vendor too long":                          "tenant@vendorlunghissimo=1",
	}
	for name, value := range cases {
		if got := SanitizeTracestate(value); got != "" {
			t.Fatalf("%s: tracestate kept = %q", name, got)
		}
	}
}

func TestTracestateAcceptsTheMultiTenantKey(t *testing.T) {
	value := "fw529a3039@dt=00f067aa0ba902b7"

	if got := SanitizeTracestate(value); got != value {
		t.Fatalf("tracestate multi-tenant = %q", got)
	}
}

func TestTracestateBeyondThirtyTwoMembersIsTrimmedFromTheTail(t *testing.T) {
	members := make([]string, 0, 40)
	for i := range 40 {
		members = append(members, "k"+string(rune('a'+i%26))+string(rune('a'+i/26))+"=v")
	}

	got := SanitizeTracestate(strings.Join(members, ","))

	kept := strings.Split(got, ",")
	if len(kept) != MaxTracestateMembers {
		t.Fatalf("members kept = %d", len(kept))
	}
	if kept[0] != members[0] {
		t.Fatalf("the head was not preserved: %q", kept[0])
	}
}

func TestTracestateBeyondTheByteCapIsTrimmed(t *testing.T) {
	long := strings.Repeat("v", 100)
	members := make([]string, 0, 10)
	for i := range 10 {
		members = append(members, "k"+string(rune('a'+i))+"="+long)
	}

	got := SanitizeTracestate(strings.Join(members, ","))

	if len(got) > MaxTracestateBytes {
		t.Fatalf("tracestate %d bytes long", len(got))
	}
	if !strings.HasPrefix(got, members[0]) {
		t.Fatalf("the head was not preserved: %q", got)
	}
}

func TestSanitizeKeepsTheFullContext(t *testing.T) {
	headers := map[string]string{
		"Traceparent": validTraceparent,
		"Tracestate":  "rojo=1",
		"Baggage":     "userId=42",
	}

	Sanitize(headers)

	if headers[HeaderTraceparent] != validTraceparent || headers[HeaderTracestate] != "rojo=1" {
		t.Fatalf("headers = %v", headers)
	}
	if headers[HeaderBaggage] != "userId=42" {
		t.Fatalf("baggage = %q", headers[HeaderBaggage])
	}
}

func TestSanitizeRecognizesHeaderNamesInAnyCase(t *testing.T) {
	headers := map[string]string{
		"TRACEPARENT": validTraceparent,
		"tracestate":  "rojo=1",
		"bAgGaGe":     "userId=42",
	}

	Sanitize(headers)

	if headers[HeaderTraceparent] != validTraceparent {
		t.Fatalf("traceparent = %v", headers)
	}
	if headers[HeaderTracestate] != "rojo=1" || headers[HeaderBaggage] != "userId=42" {
		t.Fatalf("headers = %v", headers)
	}
	for _, name := range []string{"TRACEPARENT", "tracestate", "bAgGaGe"} {
		if _, present := headers[name]; present {
			t.Fatalf("the non-canonical name %q remained: %v", name, headers)
		}
	}
}

func TestSanitizeDropsTracestateWithoutAValidTraceparent(t *testing.T) {
	headers := map[string]string{
		"Traceparent": "rotto",
		"Tracestate":  "rojo=1",
	}

	Sanitize(headers)

	if len(headers) != 0 {
		t.Fatalf("headers = %v", headers)
	}
}

// Sentry correlates with Sentry-Trace, not with traceparent: tying baggage to
// the W3C context would switch off the dynamic sampling that works today.
func TestSanitizeKeepsBaggageWithoutTraceparent(t *testing.T) {
	headers := map[string]string{"Baggage": "sentry-trace_id=abc,sentry-public_key=k"}

	Sanitize(headers)

	if headers[HeaderBaggage] != "sentry-trace_id=abc,sentry-public_key=k" {
		t.Fatalf("baggage = %v", headers)
	}
}

func TestBaggageDropsMembersWithASensitiveKey(t *testing.T) {
	value := "userId=42,session_id=s1,api-key=k,x.auth.token=t,password=p,cookie=c,secret=s,credential=c,access_key=a,private-key=pk,authorization=b"

	if got := SanitizeBaggage(value); got != "userId=42" {
		t.Fatalf("baggage = %q", got)
	}
}

func TestBaggageIgnoresMalformedMembersWithoutLosingTheOthers(t *testing.T) {
	if got := SanitizeBaggage("userId=42,rotto,tenant=acme"); got != "userId=42,tenant=acme" {
		t.Fatalf("baggage = %q", got)
	}
}

func TestBaggageKeepsTheMemberProperties(t *testing.T) {
	if got := SanitizeBaggage("userId=42;serverNode=DF:28"); got != "userId=42;serverNode=DF:28" {
		t.Fatalf("baggage = %q", got)
	}
}

func TestBaggageDropsTheMemberBeyondThePerMemberCap(t *testing.T) {
	oversized := "big=" + strings.Repeat("x", MaxBaggageMemberBytes)

	if got := SanitizeBaggage("userId=42," + oversized); got != "userId=42" {
		t.Fatalf("baggage = %q", got)
	}
}

func TestBaggageBeyondTheTotalCapIsTrimmedFromTheTail(t *testing.T) {
	chunk := strings.Repeat("x", 1000)
	members := make([]string, 0, 12)
	for i := range 12 {
		members = append(members, "k"+string(rune('a'+i))+"="+chunk)
	}

	got := SanitizeBaggage(strings.Join(members, ","))

	if len(got) > MaxBaggageBytes {
		t.Fatalf("baggage %d bytes long", len(got))
	}
	if !strings.HasPrefix(got, members[0]) {
		t.Fatalf("the head was not preserved: %q", got)
	}
}

func TestBaggageBeyondTheMemberCountIsTrimmed(t *testing.T) {
	members := make([]string, 0, MaxBaggageMembers+20)
	for i := range MaxBaggageMembers + 20 {
		members = append(members, "k"+string(rune('a'+i%26))+string(rune('a'+i/26))+"=v")
	}

	got := SanitizeBaggage(strings.Join(members, ","))

	if kept := strings.Count(got, ",") + 1; kept != MaxBaggageMembers {
		t.Fatalf("members kept = %d", kept)
	}
}

func TestBaggageRejectsValuesWithDisallowedCharacters(t *testing.T) {
	if got := SanitizeBaggage("userId=4 2,tenant=\"acme\",ok=1"); got != "ok=1" {
		t.Fatalf("baggage = %q", got)
	}
}
