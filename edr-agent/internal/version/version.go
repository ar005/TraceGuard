// internal/version/version.go
// Build metadata injected via ldflags at compile time.
// Usage:  go build -ldflags "-X .../version.Version=v1.2.3 -X .../version.GitCommit=abc123 ..."

package version

import (
	"fmt"
	"runtime"
)

// These variables are set at build time via -ldflags.
var (
	Version   = "dev"
	GitCommit = "unknown"
	GitBranch = "unknown"
	BuildTime = "unknown"
)

// Info returns a structured summary of build metadata.
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	GitBranch string `json:"git_branch"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the current build info.
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		GitBranch: GitBranch,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String returns a single-line human-readable version string.
func (i Info) String() string {
	return fmt.Sprintf("%s (commit=%s branch=%s built=%s go=%s %s)",
		i.Version, short(i.GitCommit, 8), i.GitBranch, i.BuildTime, i.GoVersion, i.Platform)
}

// Short returns just "version (commit)".
func Short() string {
	return fmt.Sprintf("%s (%s)", Version, short(GitCommit, 8))
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
