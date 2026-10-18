package version

import "testing"

func TestInfoExposesTheFullContract(t *testing.T) {
	previousTag, previousSHA, previousBuildTime := Tag, SHA, BuildTime
	t.Cleanup(func() { Tag, SHA, BuildTime = previousTag, previousSHA, previousBuildTime })
	Tag = "v1.2.3"
	SHA = "0123456789abcdef"
	BuildTime = "2026-08-12T00:00:00Z"
	t.Setenv("APP_ENV", "production")

	info := Info()
	if info.App != "closeyourit-ingest" || info.Tag != Tag || info.SHA != SHA || info.ShortSHA != "0123456" {
		t.Fatalf("identity=%+v", info)
	}
	if info.BuildTime != BuildTime || info.Environment != "production" || info.GoVersion == "" {
		t.Fatalf("runtime=%+v", info)
	}
}

func TestInfoUsesUnknownWithoutMetadata(t *testing.T) {
	previousTag, previousSHA, previousBuildTime := Tag, SHA, BuildTime
	t.Cleanup(func() { Tag, SHA, BuildTime = previousTag, previousSHA, previousBuildTime })
	Tag, SHA, BuildTime = "", "", ""
	t.Setenv("APP_ENV", "")

	info := Info()
	if info.Tag != "unknown" || info.SHA != "unknown" || info.ShortSHA != "unknown" || info.Environment != "unknown" {
		t.Fatalf("fallback=%+v", info)
	}
}
