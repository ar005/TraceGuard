// internal/version/version.go
// Build metadata injected via ldflags at compile time.
// Usage:  go build -ldflags "-X .../version.Version=v1.2.3 -X .../version.GitCommit=abc123 ..."

package version

import "fmt"

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

func String() string {
	return fmt.Sprintf("%s (commit=%s built=%s)", Version, short(GitCommit, 8), BuildTime)
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
