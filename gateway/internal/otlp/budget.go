package otlp

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaxWireBytes = 1024 * 1024
const MaxBodyBytes = 5 * 1024 * 1024
const MaxItems = 1000

// This denylist applies to semantic KeyValue names, never OTLP structural IDs.
var privateKey = regexp.MustCompile(`(?i)(pass|secret|token|bearer|api[._-]?key|authorization|cookie|csrf|session|pin|credit|card|cvv|pan|iban|e[._-]?mail|phone|telephone|mobile|dob|birth|ssn|passport|user[._-]?(id|name)|client[._-]?address|db[._-]?(statement|query)|sql)`)
var emailValue = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
var bearerValue = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]+`)
var credentialValue = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+`)
var nativeCredentialValue = regexp.MustCompile(`\bcyi_[A-Za-z0-9]{40}\b`)
var urlValue = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s<>"\x60]+`)
var queryValue = regexp.MustCompile(`([?&][A-Za-z0-9_.%\-]+=)[^\s&#]*`)

func scrubString(value string) string {
	value = urlValue.ReplaceAllStringFunc(value, scrubURL)
	value = nativeCredentialValue.ReplaceAllString(value, "[Filtered]")
	value = emailValue.ReplaceAllString(value, "[Filtered]")
	value = bearerValue.ReplaceAllString(value, "Bearer [Filtered]")
	value = credentialValue.ReplaceAllString(value, "${1}=[Filtered]")
	return queryValue.ReplaceAllString(value, "${1}[Filtered]")
}

func asMap(value any) map[string]any { result, _ := value.(map[string]any); return result }
func asSlice(value any) []any        { result, _ := value.([]any); return result }

// Budget attributes before scrubbing: a secret-heavy payload still consumes its
// original quota, and identity-bearing metric attributes are never truncated.
func validAttributes(value any) bool {
	return validAttributesWithCredential(value, "")
}

func validAttributesWithCredential(value any, credential string) bool {
	attrs := asSlice(value)
	if len(attrs) > 128 {
		return false
	}
	encoded, err := json.Marshal(attrs)
	if err != nil || len(encoded) > 64*1024 {
		return false
	}
	seen := map[string]bool{}
	for _, raw := range attrs {
		attribute := asMap(raw)
		key, _ := attribute["key"].(string)
		filteredKey := filteredAttributeKey(key, credential)
		if seen[filteredKey] || len(key) > 256 || !validDepthWithCredential(attribute["value"], 0, credential) {
			return false
		}
		seen[filteredKey] = true
	}
	return true
}

func validDepth(value any, depth int) bool {
	return validDepthWithCredential(value, depth, "")
}

func validDepthWithCredential(value any, depth int, credential string) bool {
	if depth > 8 {
		return false
	}
	v := asMap(value)
	if raw, present := v["bytesValue"]; present {
		encoded, ok := raw.(string)
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if !ok || err != nil || !utf8.Valid(decoded) {
			return false
		}
	}
	for _, entry := range asSlice(asMap(v["arrayValue"])["values"]) {
		if !validDepthWithCredential(entry, depth+1, credential) {
			return false
		}
	}
	seen := map[string]bool{}
	for _, entry := range asSlice(asMap(v["kvlistValue"])["values"]) {
		key, _ := asMap(entry)["key"].(string)
		filteredKey := filteredAttributeKey(key, credential)
		if seen[filteredKey] || len(key) > 256 || !validDepthWithCredential(asMap(entry)["value"], depth+1, credential) {
			return false
		}
		seen[filteredKey] = true
	}
	return true
}

func scrub(value any) any {
	switch v := value.(type) {
	case string:
		return scrubString(v)
	case []any:
		for i, entry := range v {
			v[i] = scrub(entry)
		}
		return v
	case map[string]any:
		if encoded, ok := v["bytesValue"].(string); ok {
			v["bytesValue"] = scrubUTF8Bytes(encoded, scrubString)
			return v
		}
		if key, ok := v["key"].(string); ok && privateKey.MatchString(key) {
			v["key"] = scrubString(key)
			v["value"] = map[string]any{"stringValue": "[Filtered]"}
			return v
		}
		// Parse the original URL before generic text filtering can change userinfo.
		if key, ok := v["key"].(string); ok && (key == "url.full" || key == "http.url") {
			av := asMap(v["value"])
			if raw, ok := av["stringValue"].(string); ok {
				av["stringValue"] = scrubURL(raw)
			}
		}
		for key, entry := range v {
			v[key] = scrub(entry)
		}
		return v
	default:
		return value
	}
}

func countSignal(signal string, body map[string]any) int {
	resourceKey, scopeKey, recordKey := signalKeys(signal)
	count := 0
	for _, r := range asSlice(body[resourceKey]) {
		for _, s := range asSlice(asMap(r)[scopeKey]) {
			for _, record := range asSlice(asMap(s)[recordKey]) {
				if signal != "metrics" {
					count++
					continue
				}
				for _, kind := range []string{"gauge", "sum", "histogram", "exponentialHistogram", "summary"} {
					count += len(asSlice(asMap(asMap(record)[kind])["dataPoints"]))
				}
			}
		}
	}
	return count
}

func signalKeys(signal string) (string, string, string) {
	switch signal {
	case "traces":
		return "resourceSpans", "scopeSpans", "spans"
	case "metrics":
		return "resourceMetrics", "scopeMetrics", "metrics"
	default:
		return "resourceLogs", "scopeLogs", "logRecords"
	}
}

func filterSignal(signal string, body map[string]any, credentials ...string) int {
	credential := ""
	if len(credentials) > 0 {
		credential = credentials[0]
	}
	resourceKey, scopeKey, recordKey := signalKeys(signal)
	rejected := 0
	resources := []any{}
	for _, r := range asSlice(body[resourceKey]) {
		rm := asMap(r)
		resourceValid := validAttributesWithCredential(asMap(rm["resource"])["attributes"], credential)
		scopes := []any{}
		for _, s := range asSlice(rm[scopeKey]) {
			sm := asMap(s)
			scopeValid := resourceValid && validAttributesWithCredential(asMap(sm["scope"])["attributes"], credential)
			kept := []any{}
			for _, record := range asSlice(sm[recordKey]) {
				rec := asMap(record)
				if signal == "metrics" {
					for _, kind := range []string{"gauge", "sum", "histogram", "exponentialHistogram", "summary"} {
						data := asMap(rec[kind])
						if data == nil {
							continue
						}
						points := []any{}
						for _, p := range asSlice(data["dataPoints"]) {
							if kind != "summary" && scopeValid && validRecord(asMap(p), credential) {
								points = append(points, p)
							} else {
								rejected++
							}
						}
						data["dataPoints"] = points
						if len(points) > 0 {
							kept = append(kept, record)
						}
					}
				} else if scopeValid && validRecord(rec, credential) {
					kept = append(kept, record)
				} else {
					rejected++
				}
			}
			sm[recordKey] = kept
			if len(kept) > 0 {
				scopes = append(scopes, sm)
			}
		}
		rm[scopeKey] = scopes
		if len(scopes) > 0 {
			resources = append(resources, rm)
		}
	}
	body[resourceKey] = resources
	scrub(body)
	return rejected
}

func validRecord(record map[string]any, credential string) bool {
	if !validAttributesWithCredential(record["attributes"], credential) || !validDepthWithCredential(record["body"], 0, credential) {
		return false
	}
	for _, key := range []string{"events", "links", "exemplars"} {
		for _, e := range asSlice(record[key]) {
			m := asMap(e)
			if !validAttributesWithCredential(m["attributes"], credential) || !validAttributesWithCredential(m["filteredAttributes"], credential) {
				return false
			}
		}
	}
	return true
}

func signalForPath(path string) string {
	if strings.HasPrefix(path, "/v1/") {
		switch strings.TrimPrefix(path, "/v1/") {
		case "traces", "metrics", "logs":
			return strings.TrimPrefix(path, "/v1/")
		}
	}
	return ""
}

func scrubURL(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return "[Filtered URL]"
	}
	u.User = nil
	q := u.Query()
	for key := range q {
		q[key] = []string{"[Filtered]"}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// A bearer can have an opaque format beyond recognized token patterns. Remove
// the actual authenticated credential even when a producer put it in free text.
func scrubCredential(value any, credential string) any {
	switch v := value.(type) {
	case string:
		return strings.ReplaceAll(v, credential, "[Filtered]")
	case []any:
		for i, entry := range v {
			v[i] = scrubCredential(entry, credential)
		}
	case map[string]any:
		if encoded, ok := v["bytesValue"].(string); ok {
			v["bytesValue"] = scrubUTF8Bytes(encoded, func(text string) string { return strings.ReplaceAll(text, credential, "[Filtered]") })
			return v
		}
		for key, entry := range v {
			v[key] = scrubCredential(entry, credential)
		}
	}
	return value
}

func scrubUTF8Bytes(encoded string, filter func(string) string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !utf8.Valid(decoded) {
		// Admission rejects this item before scrubbing; keep this helper fail-closed.
		return base64.StdEncoding.EncodeToString([]byte("[Filtered]"))
	}
	return base64.StdEncoding.EncodeToString([]byte(filter(string(decoded))))
}

func filteredAttributeKey(key, credential string) string {
	key = scrubString(key)
	if credential != "" {
		key = strings.ReplaceAll(key, credential, "[Filtered]")
	}
	return key
}
