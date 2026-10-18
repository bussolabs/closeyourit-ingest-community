// Package tracecontext decides which of the W3C correlation headers the gateway
// is entitled to repeat to the upstream. The gateway sits between the
// customer's SDK and CloseYourIt: if it repeated them blindly it would become a
// channel through which anyone who knows the endpoint pushes arbitrary data
// inside the perimeter, persisted in the queue on top of that. Here propagation
// is a permission that every value has to earn.
//
// References: W3C Trace Context (traceparent, tracestate) and W3C Baggage.
package tracecontext

import (
	"net/textproto"
	"strings"
)

// Header names are in Go canonical form. On the HTTP wire case does not
// matter, but keeping a single form prevents the same header from ending up
// twice in the envelope map with two different spellings.
const (
	HeaderTraceparent = "Traceparent"
	HeaderTracestate  = "Tracestate"
	HeaderBaggage     = "Baggage"
)

// The caps are the ones recommended by the specifications: raising them would
// not make correlation more precise, only someone using the header to carry
// something else exceeds them.
const (
	MaxTracestateMembers  = 32
	MaxTracestateBytes    = 512
	MaxBaggageMembers     = 180
	MaxBaggageBytes       = 8192
	MaxBaggageMemberBytes = 4096
)

// traceparentBaseLength is the exact length of a version 00 traceparent:
// two version digits, trace id, span id, flags and the three dashes.
const traceparentBaseLength = 55

// sensitiveBaggageKeys lists what no trace needs to know in order to correlate
// and what a misconfigured SDK can nevertheless propagate without noticing.
// The comparison is by substring on the normalized key, not by equality:
// "x.auth.token" and "sessionId" hide the same risk as "token" and "session".
// The Sentry baggage keys (sentry-trace_id, sentry-public_key,
// sentry-sample_rate) contain none of these entries and keep passing.
var sensitiveBaggageKeys = []string{
	"access_key", "api_key", "apikey", "authorization", "cookie", "credential",
	"passwd", "password", "private_key", "secret", "session", "token",
}

// Sanitize rewrites in place only the trace context headers present in
// headers, dropping those that fail the policy and bringing names written in
// any case back to canonical form.
func Sanitize(headers map[string]string) {
	if headers == nil {
		return
	}
	received := make(map[string]string, 3)
	for name, value := range headers {
		switch canonical := textproto.CanonicalMIMEHeaderKey(name); canonical {
		case HeaderTraceparent, HeaderTracestate, HeaderBaggage:
			received[canonical] = value
			delete(headers, name)
		}
	}

	traceparent := SanitizeTraceparent(received[HeaderTraceparent])
	if traceparent != "" {
		headers[HeaderTraceparent] = traceparent
		// Without a trace to belong to, the tracestate correlates nothing:
		// it would only be a list of opaque pairs forwarded out of inertia.
		// The specification asks to discard it.
		if tracestate := SanitizeTracestate(received[HeaderTracestate]); tracestate != "" {
			headers[HeaderTracestate] = tracestate
		}
	}
	// Baggage is not tied to traceparent: Sentry pairs it with Sentry-Trace
	// and the gateway already forwards it today. Binding it to the W3C context
	// would switch off the dynamic sampling of an SDK that emits no traceparent.
	if baggage := SanitizeBaggage(received[HeaderBaggage]); baggage != "" {
		headers[HeaderBaggage] = baggage
	}
}

// SanitizeTraceparent returns the traceparent to propagate, an empty string if
// the value does not conform. A made-up traceparent is no better than no
// traceparent: it would correlate the request to a trace that does not exist.
func SanitizeTraceparent(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < traceparentBaseLength || !printableASCII(value) {
		return ""
	}
	if value[2] != '-' || value[35] != '-' || value[52] != '-' {
		return ""
	}

	version, traceID, spanID, flags := value[0:2], value[3:35], value[36:52], value[53:55]
	if !lowerHex(version) || version == "ff" || !lowerHex(flags) {
		return ""
	}
	if !lowerHex(traceID) || allZero(traceID) || !lowerHex(spanID) || allZero(spanID) {
		return ""
	}

	if version == "00" {
		if len(value) != traceparentBaseLength {
			return ""
		}
		return value
	}
	// A newer version may add fields: they are propagated unchanged,
	// provided they are separated from the known ones as the specification prescribes.
	if len(value) > traceparentBaseLength && value[traceparentBaseLength] != '-' {
		return ""
	}
	return value
}

// SanitizeTracestate returns the tracestate to propagate, trimmed to the caps
// of the specification. A single malformed member invalidates the whole header:
// the specification forbids fixing it, and keeping the rest would mean handing
// the upstream a list that nobody actually wrote.
func SanitizeTracestate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !printableASCII(value) {
		return ""
	}

	parts := strings.Split(value, ",")
	members := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		member := strings.TrimSpace(part)
		if member == "" {
			// The specification allows empty members and asks to ignore them.
			continue
		}
		key, memberValue, separated := strings.Cut(member, "=")
		if !separated || !validTracestateKey(key) || !validTracestateValue(memberValue) {
			return ""
		}
		if _, duplicate := seen[key]; duplicate {
			return ""
		}
		seen[key] = struct{}{}
		members = append(members, key+"="+memberValue)
	}

	return joinWithinLimits(members, MaxTracestateMembers, MaxTracestateBytes)
}

// SanitizeBaggage returns the baggage to propagate, without the members that
// are malformed or that carry credentials. Here a malformed member does not
// doom the others: baggage is a collection of independent annotations and the
// specification asks to ignore the ones that are not understood.
func SanitizeBaggage(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !printableASCII(value) {
		return ""
	}

	parts := strings.Split(value, ",")
	members := make([]string, 0, len(parts))
	for _, part := range parts {
		member, ok := sanitizeBaggageMember(strings.TrimSpace(part))
		if !ok {
			continue
		}
		members = append(members, member)
	}

	return joinWithinLimits(members, MaxBaggageMembers, MaxBaggageBytes)
}

func sanitizeBaggageMember(member string) (string, bool) {
	if member == "" || len(member) > MaxBaggageMemberBytes {
		return "", false
	}
	definition, properties, _ := strings.Cut(member, ";")
	key, value, separated := strings.Cut(strings.TrimSpace(definition), "=")
	key = strings.TrimSpace(key)
	if !separated || !validBaggageKey(key) || !validBaggageValue(strings.TrimSpace(value)) {
		return "", false
	}
	if sensitiveBaggageKey(key) {
		return "", false
	}

	sanitized := key + "=" + strings.TrimSpace(value)
	if properties == "" {
		return sanitized, true
	}
	for _, property := range strings.Split(properties, ";") {
		property = strings.TrimSpace(property)
		propertyKey, propertyValue, hasValue := strings.Cut(property, "=")
		propertyKey = strings.TrimSpace(propertyKey)
		if !validBaggageKey(propertyKey) {
			return "", false
		}
		if !hasValue {
			sanitized += ";" + propertyKey
			continue
		}
		propertyValue = strings.TrimSpace(propertyValue)
		if !validBaggageValue(propertyValue) {
			return "", false
		}
		sanitized += ";" + propertyKey + "=" + propertyValue
	}
	return sanitized, true
}

func sensitiveBaggageKey(key string) bool {
	normalized := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(key))
	for _, sensitive := range sensitiveBaggageKeys {
		if strings.Contains(normalized, sensitive) {
			return true
		}
	}
	return false
}

// joinWithinLimits cuts from the tail until the list fits within the caps: in
// both specifications the most recent members are at the head, so it is the
// tail that holds the most distant context, the least useful for correlation.
func joinWithinLimits(members []string, maxMembers, maxBytes int) string {
	if len(members) > maxMembers {
		members = members[:maxMembers]
	}
	joined := strings.Join(members, ",")
	for len(joined) > maxBytes && len(members) > 0 {
		members = members[:len(members)-1]
		joined = strings.Join(members, ",")
	}
	return joined
}

func validTracestateKey(key string) bool {
	if key == "" || len(key) > 256 {
		return false
	}
	if at := strings.IndexByte(key, '@'); at >= 0 {
		tenant, vendor := key[:at], key[at+1:]
		if tenant == "" || len(tenant) > 241 || !(lowerAlpha(tenant[0]) || digit(tenant[0])) {
			return false
		}
		if vendor == "" || len(vendor) > 14 || !lowerAlpha(vendor[0]) {
			return false
		}
		return tracestateKeyChars(tenant[1:]) && tracestateKeyChars(vendor[1:])
	}
	return lowerAlpha(key[0]) && tracestateKeyChars(key[1:])
}

func tracestateKeyChars(value string) bool {
	for i := range len(value) {
		c := value[i]
		if lowerAlpha(c) || digit(c) || c == '_' || c == '-' || c == '*' || c == '/' {
			continue
		}
		return false
	}
	return true
}

func validTracestateValue(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if c == ' ' {
			// The last character cannot be a space.
			if i == len(value)-1 {
				return false
			}
			continue
		}
		if !((c >= 0x21 && c <= 0x2B) || (c >= 0x2D && c <= 0x3C) || (c >= 0x3E && c <= 0x7E)) {
			return false
		}
	}
	return true
}

// validBaggageKey applies the RFC 7230 token, which is what the Baggage
// specification requires for keys and for property keys.
func validBaggageKey(key string) bool {
	if key == "" {
		return false
	}
	for i := range len(key) {
		c := key[i]
		if lowerAlpha(c) || (c >= 'A' && c <= 'Z') || digit(c) {
			continue
		}
		if strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

// validBaggageValue allows the specification's baggage-octet: no spaces,
// double quotes, commas, semicolons or backslashes, which are the characters
// that would break the list apart.
func validBaggageValue(value string) bool {
	for i := range len(value) {
		c := value[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x2B) || (c >= 0x25 && c <= 0x3A) ||
			(c >= 0x3C && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) {
			continue
		}
		return false
	}
	return true
}

func printableASCII(value string) bool {
	for i := range len(value) {
		if value[i] < 0x20 || value[i] > 0x7E {
			return false
		}
	}
	return true
}

func lowerHex(value string) bool {
	for i := range len(value) {
		c := value[i]
		if !digit(c) && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func allZero(value string) bool {
	return strings.Count(value, "0") == len(value)
}

func lowerAlpha(c byte) bool { return c >= 'a' && c <= 'z' }

func digit(c byte) bool { return c >= '0' && c <= '9' }
