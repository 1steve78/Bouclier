package cli

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

const AppVersion = "0.1.0-dev"

// RunVersion outputs application version and build metadata to w.
func RunVersion(w io.Writer) error {
	fmt.Fprintf(w, "Bouclier v%s\n", AppVersion)
	fmt.Fprintf(w, "  Go version: %s\n", runtime.Version())
	fmt.Fprintf(w, "  Platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				rev := setting.Value
				if len(rev) > 12 {
					rev = rev[:12]
				}
				fmt.Fprintf(w, "  Commit:     %s\n", rev)
			case "vcs.time":
				fmt.Fprintf(w, "  Build time: %s\n", setting.Value)
			case "vcs.modified":
				if setting.Value == "true" {
					fmt.Fprintf(w, "  Modified:   true\n")
				}
			}
		}
	}
	return nil
}
