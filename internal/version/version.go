// Package version exposes build-time identification for the SealKeeper binary.
//
// The three vars are populated via -ldflags in the build pipeline (see Makefile
// and .github/workflows/release.yml). When the binary is built without those
// flags they keep their `unknown`/`dev` defaults — which is fine for tests.
package version

import "runtime/debug"

var (
	// Version is the SemVer tag or `dev` for unreleased builds.
	Version = "dev"
	// Commit is the short git SHA the binary was built from.
	Commit = "unknown"
	// BuildDate is an RFC3339 UTC timestamp recorded at build time.
	BuildDate = "unknown"
)

// String returns "<version> (<commit>, <date>)".
func String() string {
	return Version + " (" + Commit + ", " + BuildDate + ")"
}

// GoVersion returns the Go toolchain version embedded in the binary, when
// available. Useful for the `version` sub-command and `/version` HTTP route.
func GoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}
	return "unknown"
}
