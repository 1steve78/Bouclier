package tui

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines the keybindings across the TUI.
type KeyMap struct {
	Quit         key.Binding
	ForceQuit    key.Binding
	Help         key.Binding
	Back         key.Binding
	Confirm      key.Binding
	CancelScan   key.Binding
	NewScan      key.Binding
	ViewFindings key.Binding
	ViewCoverage key.Binding
	Export       key.Binding
	Up           key.Binding
	Down         key.Binding
	Left         key.Binding
	Right        key.Binding
	Tab          key.Binding
	ShiftTab     key.Binding
	Filter1      key.Binding
	Filter2      key.Binding
	Filter3      key.Binding
	Filter4      key.Binding
	Filter5      key.Binding
	Filter6      key.Binding
	PrevItem     key.Binding
	NextItem     key.Binding
}

// DefaultKeyMap returns the default set of keybindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Quit: key.NewBinding(
			key.WithKeys("q"),
			key.WithHelp("q", "quit"),
		),
		ForceQuit: key.NewBinding(
			key.WithKeys("ctrl+c"),
			key.WithHelp("ctrl+c", "force quit"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc", "backspace"),
			key.WithHelp("esc", "back"),
		),
		Confirm: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select / start"),
		),
		CancelScan: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "cancel scan"),
		),
		NewScan: key.NewBinding(
			key.WithKeys("n", "s"),
			key.WithHelp("n", "new scan"),
		),
		ViewFindings: key.NewBinding(
			key.WithKeys("f"),
			key.WithHelp("f", "findings"),
		),
		ViewCoverage: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "coverage"),
		),
		Export: key.NewBinding(
			key.WithKeys("e"),
			key.WithHelp("e", "export"),
		),
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "down"),
		),
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←/h", "left"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→/l", "right"),
		),
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "next"),
		),
		ShiftTab: key.NewBinding(
			key.WithKeys("shift+tab"),
			key.WithHelp("shift+tab", "prev"),
		),
		Filter1: key.NewBinding(
			key.WithKeys("1"),
			key.WithHelp("1", "all"),
		),
		Filter2: key.NewBinding(
			key.WithKeys("2"),
			key.WithHelp("2", "crit"),
		),
		Filter3: key.NewBinding(
			key.WithKeys("3"),
			key.WithHelp("3", "high"),
		),
		Filter4: key.NewBinding(
			key.WithKeys("4"),
			key.WithHelp("4", "med"),
		),
		Filter5: key.NewBinding(
			key.WithKeys("5"),
			key.WithHelp("5", "low"),
		),
		Filter6: key.NewBinding(
			key.WithKeys("6"),
			key.WithHelp("6", "info"),
		),
		PrevItem: key.NewBinding(
			key.WithKeys("p", "left"),
			key.WithHelp("p", "prev"),
		),
		NextItem: key.NewBinding(
			key.WithKeys("n", "right"),
			key.WithHelp("n", "next"),
		),
	}
}
