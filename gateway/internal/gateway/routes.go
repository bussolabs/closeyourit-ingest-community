package gateway

import "regexp"

type routeRule struct {
	kind    string
	pattern *regexp.Regexp
}

var ingestRoutes = []routeRule{
	{kind: "minidump", pattern: regexp.MustCompile(`^/api/[^/]+/minidump/?$`)},
	{kind: "events", pattern: regexp.MustCompile(`^/api/v1/projects/[^/]+/events/?$`)},
	{kind: "metrics", pattern: regexp.MustCompile(`^/api/v1/projects/[^/]+/metrics/?$`)},
	{kind: "logs", pattern: regexp.MustCompile(`^/api/v1/projects/[^/]+/logs/?$`)},
	{kind: "pageviews", pattern: regexp.MustCompile(`^/api/v1/projects/[^/]+/pageviews/?$`)},
	{kind: "replays", pattern: regexp.MustCompile(`^/api/v1/projects/[^/]+/replays/?$`)},
	{kind: "releases", pattern: regexp.MustCompile(`^/api/v1/projects/[^/]+/releases/?$`)},
	{kind: "crons", pattern: regexp.MustCompile(`^/api/v1/projects/[^/]+/crons/[^/]+/check_in/?$`)},
	{kind: "sentry", pattern: regexp.MustCompile(`^/api/[^/]+/(?:envelope|store)/?$`)},
	{kind: "servers", pattern: regexp.MustCompile(`^/api/v1/servers/samples/?$`)},
}

func classifyRoute(path string) (string, bool) {
	for _, rule := range ingestRoutes {
		if rule.pattern.MatchString(path) {
			return rule.kind, true
		}
	}
	return "", false
}
