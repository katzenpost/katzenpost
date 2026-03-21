// Package common provides shared utilities for katzenpost CLI tools.
package common

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/carlmjohnson/versioninfo"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
)

// ExecuteWithFang executes a cobra command using fang with standard katzenpost options.
// This reduces boilerplate across all CLI tools by providing a common execution pattern.
func ExecuteWithFang(cmd *cobra.Command) {
	if err := fang.Execute(
		context.Background(),
		cmd,
		fang.WithVersion(versioninfo.Short()),
		fang.WithErrorHandler(ErrorHandlerWithUsage(cmd)),
	); err != nil {
		os.Exit(1)
	}
}

// ErrorHandlerWithUsage creates a custom error handler that displays error messages
// followed by usage help for CLI argument errors. This provides better user experience
// by showing both the error and how to use the command correctly.
func ErrorHandlerWithUsage(cmd *cobra.Command) fang.ErrorHandler {
	return func(w io.Writer, styles fang.Styles, err error) {
		// Print the styled error header and message
		_, _ = fmt.Fprintln(w, styles.ErrorHeader.String())
		_, _ = fmt.Fprintln(w, styles.ErrorText.Render(err.Error()+"."))
		_, _ = fmt.Fprintln(w)

		// Check if this is a usage error that should show help
		if isUsageError(err) {
			// Print the usage help
			helpFunc := cmd.HelpFunc()
			if helpFunc != nil {
				// Create a colorprofile writer for the help output
				_ = colorprofile.NewWriter(w, nil)
				helpFunc(cmd, []string{})
			}
		} else {
			// For non-usage errors, just show the "Try --help" suggestion
			_, _ = fmt.Fprintln(w, lipgloss.JoinHorizontal(
				lipgloss.Left,
				styles.ErrorText.UnsetWidth().Render("Try"),
				styles.Program.Flag.Render("--help"),
				styles.ErrorText.UnsetWidth().UnsetMargins().UnsetTransform().PaddingLeft(1).Render("for usage."),
			))
			_, _ = fmt.Fprintln(w)
		}
	}
}

// isUsageError determines if an error is related to CLI usage and should trigger
// automatic display of usage help. This includes flag errors, unknown commands,
// invalid arguments, and configuration file errors.
func isUsageError(err error) bool {
	s := err.Error()
	for _, prefix := range []string{
		"flag needs an argument:",
		"unknown flag:",
		"unknown shorthand flag:",
		"unknown command",
		"invalid argument",
		"required flag",
		"accepts",
		"arg(s), received",
		"failed to load config file",
		"failed to load server config file",
		"config file must be specified",
	} {
		if strings.Contains(s, prefix) {
			return true
		}
	}
	return false
}
