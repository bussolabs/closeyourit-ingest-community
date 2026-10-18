package version

import (
	"os"
	"runtime"
)

var (
	Tag       = "unknown"
	SHA       = "unknown"
	BuildTime = "unknown"
)

type Build struct {
	App         string `json:"app"`
	Tag         string `json:"tag"`
	SHA         string `json:"sha"`
	ShortSHA    string `json:"short_sha"`
	BuildTime   string `json:"build_time"`
	Environment string `json:"environment"`
	GoVersion   string `json:"go_version"`
}

func Info() Build {
	return Build{
		App:         "closeyourit-ingest",
		Tag:         normalized(Tag),
		SHA:         normalized(SHA),
		ShortSHA:    shortSHA(normalized(SHA)),
		BuildTime:   normalized(BuildTime),
		Environment: envOrUnknown("APP_ENV"),
		GoVersion:   runtime.Version(),
	}
}

func normalized(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func shortSHA(sha string) string {
	if sha == "unknown" || len(sha) < 7 {
		return sha
	}
	return sha[:7]
}

func envOrUnknown(name string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return "unknown"
}
