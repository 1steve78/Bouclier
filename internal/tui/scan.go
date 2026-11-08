package tui

import (
	"context"
	"time"

	"bouclier/internal/cli"
	"bouclier/internal/config"
	tea "github.com/charmbracelet/bubbletea"
)

type scanRunnerFunc func(ctx context.Context, cfg *config.Config, opts cli.ScanOptions, onProgress cli.ScanProgressFunc) (*cli.ScanPipelineResult, error)

var scanRunner scanRunnerFunc = cli.ExecuteScanPipeline

// SetScanRunnerForTesting overrides the scan pipeline execution function for testing.
// Returns a restore function that reverts to the original runner.
func SetScanRunnerForTesting(fn scanRunnerFunc) func() {
	prev := scanRunner
	scanRunner = fn
	return func() {
		scanRunner = prev
	}
}

// StartScanCmd creates a background goroutine to execute the scan pipeline asynchronously.
// It returns a tea.Cmd that listens for progress messages from the scan channel.
func StartScanCmd(scanID uint64, ctx context.Context, cfg *config.Config, target string, msgChan chan tea.Msg) tea.Cmd {
	go func() {
		opts := cli.ScanOptions{
			Target: target,
		}

		onProgress := func(stage cli.ScanStage, state cli.StageState, message string) {
			select {
			case msgChan <- ScanProgressMsg{
				ScanID:  scanID,
				Stage:   stage,
				State:   state,
				Message: message,
			}:
			case <-ctx.Done():
			}
		}

		res, err := scanRunner(ctx, cfg, opts, onProgress)
		if err != nil {
			select {
			case msgChan <- ScanCompletedMsg{
				ScanID: scanID,
				Err:    err,
			}:
			case <-ctx.Done():
			}
			return
		}

		select {
		case msgChan <- ScanCompletedMsg{
			ScanID:        scanID,
			Assessment:    res.Assessment,
			IsSSRFBlocked: res.IsSSRFBlocked,
			Err:           nil,
		}:
		case <-ctx.Done():
		}
	}()

	return WaitForScanMsg(msgChan)
}

// WaitForScanMsg reads a single message from the scan channel.
func WaitForScanMsg(msgChan chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		if msgChan == nil {
			return nil
		}
		msg, ok := <-msgChan
		if !ok {
			return nil
		}
		return msg
	}
}

// TickCmd triggers periodic timer ticks while a scan is in progress.
func TickCmd() tea.Cmd {
	return tea.Tick(150*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}
