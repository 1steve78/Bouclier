package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Target struct {
	GOOS   string
	GOARCH string
}

var supportedTargets = []Target{
	{GOOS: "windows", GOARCH: "amd64"},
	{GOOS: "windows", GOARCH: "arm64"},
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
	{GOOS: "darwin", GOARCH: "arm64"},
	{GOOS: "darwin", GOARCH: "amd64"},
}

func main() {
	var (
		version = flag.String("version", "1.0.0", "Release version (e.g. 1.0.0)")
		commit  = flag.String("commit", "", "Git commit hash (defaults to git rev-parse)")
		date    = flag.String("date", "", "Build date UTC (defaults to current time)")
		outDir  = flag.String("outdir", "dist", "Output directory for release archives")
	)
	flag.Parse()

	if *commit == "" {
		if out, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output(); err == nil {
			*commit = strings.TrimSpace(string(out))
		} else {
			*commit = "unknown"
		}
	}
	if *date == "" {
		*date = time.Now().UTC().Format(time.RFC3339)
	}

	normVersion := strings.TrimPrefix(*version, "v")

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output dir: %v\n", err)
		os.Exit(1)
	}

	tempDir, err := os.MkdirTemp("", "bouclier-release-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	type ArchiveInfo struct {
		Filename string
		SHA256   string
	}
	var archives []ArchiveInfo

	for _, target := range supportedTargets {
		fmt.Printf("==> Building for %s/%s...\n", target.GOOS, target.GOARCH)

		binName := "bouclier"
		if target.GOOS == "windows" {
			binName += ".exe"
		}

		buildTargetDir := filepath.Join(tempDir, fmt.Sprintf("%s_%s", target.GOOS, target.GOARCH))
		if err := os.MkdirAll(buildTargetDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create target dir: %v\n", err)
			os.Exit(1)
		}
		binPath := filepath.Join(buildTargetDir, binName)

		ldflags := fmt.Sprintf("-s -w -X 'bouclier/internal/cli.Version=%s' -X 'bouclier/internal/cli.GitCommit=%s' -X 'bouclier/internal/cli.BuildDate=%s'",
			normVersion, *commit, *date)

		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", binPath, ".")
		cmd.Env = append(os.Environ(),
			"GOOS="+target.GOOS,
			"GOARCH="+target.GOARCH,
			"CGO_ENABLED=0",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "Build failed for %s/%s: %v\nOutput: %s\n", target.GOOS, target.GOARCH, err, string(out))
			os.Exit(1)
		}

		var archiveName string
		var archivePath string
		if target.GOOS == "windows" {
			archiveName = fmt.Sprintf("bouclier_v%s_%s_%s.zip", normVersion, target.GOOS, target.GOARCH)
			archivePath = filepath.Join(*outDir, archiveName)
			if err := createZipArchive(archivePath, binPath, binName); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create zip: %v\n", err)
				os.Exit(1)
			}
		} else {
			archiveName = fmt.Sprintf("bouclier_v%s_%s_%s.tar.gz", normVersion, target.GOOS, target.GOARCH)
			archivePath = filepath.Join(*outDir, archiveName)
			if err := createTarGzArchive(archivePath, binPath, binName); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create tar.gz: %v\n", err)
				os.Exit(1)
			}
		}

		sum, err := fileSHA256(archivePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to compute checksum: %v\n", err)
			os.Exit(1)
		}
		archives = append(archives, ArchiveInfo{Filename: archiveName, SHA256: sum})
		fmt.Printf("  Created %s (SHA-256: %s)\n", archiveName, sum)
	}

	checksumFile := filepath.Join(*outDir, "checksums.txt")
	f, err := os.Create(checksumFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create checksums.txt: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	for _, a := range archives {
		fmt.Fprintf(f, "%s  %s\n", a.SHA256, a.Filename)
	}
	fmt.Printf("\n==> Successfully created %d release archives and checksums.txt in %s\n", len(archives), *outDir)
}

func createZipArchive(zipPath, binPath, binName string) error {
	zf, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zf.Close()

	w := zip.NewWriter(zf)
	defer w.Close()

	if err := addFileToZip(w, binPath, binName); err != nil {
		return err
	}
	if fileExists("README.md") {
		if err := addFileToZip(w, "README.md", "README.md"); err != nil {
			return err
		}
	}
	if fileExists("LICENSE") {
		if err := addFileToZip(w, "LICENSE", "LICENSE"); err != nil {
			return err
		}
	}
	if fileExists("THIRD_PARTY_NOTICES.md") {
		if err := addFileToZip(w, "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md"); err != nil {
			return err
		}
	}
	return nil
}

func addFileToZip(w *zip.Writer, srcPath, entryName string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	info, err := src.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = entryName
	header.Method = zip.Deflate

	dst, err := w.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	return err
}

func createTarGzArchive(tarGzPath, binPath, binName string) error {
	f, err := os.Create(tarGzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	if err := addFileToTar(tw, binPath, binName, 0755); err != nil {
		return err
	}
	if fileExists("README.md") {
		if err := addFileToTar(tw, "README.md", "README.md", 0644); err != nil {
			return err
		}
	}
	if fileExists("LICENSE") {
		if err := addFileToTar(tw, "LICENSE", "LICENSE", 0644); err != nil {
			return err
		}
	}
	if fileExists("THIRD_PARTY_NOTICES.md") {
		if err := addFileToTar(tw, "THIRD_PARTY_NOTICES.md", "THIRD_PARTY_NOTICES.md", 0644); err != nil {
			return err
		}
	}
	return nil
}

func addFileToTar(tw *tar.Writer, srcPath, entryName string, mode int64) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	info, err := src.Stat()
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    entryName,
		Size:    info.Size(),
		Mode:    mode,
		ModTime: info.ModTime(),
	}

	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(tw, src)
	return err
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
