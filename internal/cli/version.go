package cli

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

var (
	// Version is the application semantic version.
	// Can be set at build time via: -ldflags "-X bouclier/internal/cli.Version=1.1.0"
	Version = "1.1.0-dev"

	// GitCommit is the commit hash at build time.
	// Can be set via: -ldflags "-X bouclier/internal/cli.GitCommit=..."
	GitCommit = ""

	// BuildDate is the UTC build timestamp.
	// Can be set via: -ldflags "-X bouclier/internal/cli.BuildDate=..."
	BuildDate = ""

	// AppVersion is an alias for Version kept for backward compatibility.
	AppVersion = "1.1.0-dev"
)

func init() {
	if Version != "" {
		AppVersion = strings.TrimPrefix(Version, "v")
	}
}

// BuildMetadata contains structured build information.
type BuildMetadata struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Built     string `json:"built"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// GetBuildMetadata returns structured build information.
func GetBuildMetadata() BuildMetadata {
	v := strings.TrimPrefix(Version, "v")
	if v == "" {
		v = strings.TrimPrefix(AppVersion, "v")
	}

	commit := GitCommit
	buildDate := BuildDate

	if commit == "" || buildDate == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				switch setting.Key {
				case "vcs.revision":
					if commit == "" {
						commit = setting.Value
						if len(commit) > 12 {
							commit = commit[:12]
						}
					}
				case "vcs.time":
					if buildDate == "" {
						buildDate = setting.Value
					}
				}
			}
		}
	}

	if commit == "" {
		commit = "unknown"
	}
	if buildDate == "" {
		buildDate = "unknown"
	}

	return BuildMetadata{
		Version:   v,
		Commit:    commit,
		Built:     buildDate,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// RunVersion outputs application version and build metadata to w.
func RunVersion(w io.Writer) error {
	meta := GetBuildMetadata()
	fmt.Fprintf(w, "Bouclier v%s\n", meta.Version)
	fmt.Fprintf(w, "  Commit:   %s\n", meta.Commit)
	fmt.Fprintf(w, "  Built:    %s\n", meta.Built)
	fmt.Fprintf(w, "  Go:       %s\n", meta.GoVersion)
	fmt.Fprintf(w, "  Platform: %s\n", meta.Platform)
	return nil
}
