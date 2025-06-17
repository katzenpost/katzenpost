//go:build ignore

// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// This file is used with go generate to build trunnel message types.
// Run: go generate ./pigeonhole/...

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	// Get the current working directory (where go generate was called)
	workDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
		os.Exit(1)
	}

	// Path to the trunnel schema file (in current directory)
	trunnelFile := filepath.Join(workDir, "pigeonhole_messages.trunnel")

	// Check if trunnel file exists
	if _, err := os.Stat(trunnelFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Trunnel file not found: %s\n", trunnelFile)
		os.Exit(1)
	}

	// Output directory for generated files (current directory)
	outputDir := workDir

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Find trunnel binary
	trunnelBinary, err := findTrunnelBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding trunnel binary: %v\n", err)
		os.Exit(1)
	}

	// Run trunnel build command
	cmd := exec.Command(trunnelBinary, "build", "--pkg", "pigeonhole", "--dir", outputDir, trunnelFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Running: %s\n", cmd.String())

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running trunnel: %v\n", err)
		os.Exit(1)
	}

	// Rename generated files to have more descriptive names
	generatedFile := filepath.Join(outputDir, "gen-marshallers.go")
	targetFile := filepath.Join(outputDir, "trunnel_messages.go")

	if _, err := os.Stat(generatedFile); err == nil {
		if err := os.Rename(generatedFile, targetFile); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not rename generated file: %v\n", err)
		} else {
			fmt.Printf("Generated: %s\n", targetFile)
		}
	}

	// Also rename the test file
	generatedTestFile := filepath.Join(outputDir, "gen-marshallers_test.go")
	targetTestFile := filepath.Join(outputDir, "trunnel_messages_test.go")

	if _, err := os.Stat(generatedTestFile); err == nil {
		if err := os.Rename(generatedTestFile, targetTestFile); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not rename generated test file: %v\n", err)
		} else {
			fmt.Printf("Generated: %s\n", targetTestFile)
		}
	}

	fmt.Println("Trunnel code generation completed successfully!")
}

// findTrunnelBinary attempts to find the trunnel binary in various locations
func findTrunnelBinary() (string, error) {
	// First try to find it in PATH
	if path, err := exec.LookPath("trunnel"); err == nil {
		return path, nil
	}

	// Try to find it in the Go module cache
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/katzenpost/trunnel")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("could not find trunnel module: %v", err)
	}

	trunnelModDir := string(output)
	trunnelModDir = trunnelModDir[:len(trunnelModDir)-1] // Remove trailing newline

	trunnelBinary := filepath.Join(trunnelModDir, "trunnel")

	// Check if the binary exists and is executable
	if info, err := os.Stat(trunnelBinary); err == nil && info.Mode()&0111 != 0 {
		return trunnelBinary, nil
	}

	// If not executable, try to make it executable
	if err := os.Chmod(trunnelBinary, 0755); err != nil {
		return "", fmt.Errorf("trunnel binary found but not executable: %s", trunnelBinary)
	}

	return trunnelBinary, nil
}
