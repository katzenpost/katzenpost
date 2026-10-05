// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, f func() error) (string, error) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	ferr := f()
	os.Stdout = old
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out), ferr
}

func TestPrintDocumentDefaultKeepsDump(t *testing.T) {
	doc, names := formatTestDoc(t)
	out, err := captureStdout(t, func() error { return printDocument(doc, names, "") })
	require.NoError(t, err)
	require.Contains(t, out, doc.String())
	require.Contains(t, out, "signed by 2 directory authorities")
}

func TestPrintDocumentFormats(t *testing.T) {
	doc, names := formatTestDoc(t)
	want, err := formatDocument(doc, "text", names)
	require.NoError(t, err)
	out, err := captureStdout(t, func() error { return printDocument(doc, names, "text") })
	require.NoError(t, err)
	require.Equal(t, want, out)

	out, err = captureStdout(t, func() error { return printDocument(doc, names, "json") })
	require.NoError(t, err)
	var v map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &v))

	out, err = captureStdout(t, func() error { return printDocument(doc, names, "yaml") })
	require.Error(t, err)
	require.Empty(t, out)
}

func TestPrintSignersLabelFormatExactly(t *testing.T) {
	doc, names := formatTestDoc(t)
	var namedFP [32]byte
	for fp, name := range names {
		if name != "" {
			namedFP = fp
		}
	}
	out, err := captureStdout(t, func() error { return printDocument(doc, names, "") })
	require.NoError(t, err)
	unnamed := fmt.Sprintf("%x", [32]byte{0xab})
	named := fmt.Sprintf("%s (%x)", names[namedFP], namedFP[:])
	want := doc.String() + fmt.Sprintf("\nPKI document for epoch %d signed by 2 directory authorities:\n  %s\n  %s\n",
		doc.Epoch, unnamed, named)
	require.Equal(t, want, out)
}

func TestFetchRejectsUnknownFormatBeforeConnecting(t *testing.T) {
	cmd := newRootCommand()
	cmd.SetArgs([]string{"--format", "yaml", "-f", filepath.Join(t.TempDir(), "missing.toml")})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	require.ErrorContains(t, err, `unknown format "yaml"`)

	cmd = newRootCommand()
	cmd.SetArgs([]string{"--format", "json", "-f", filepath.Join(t.TempDir(), "missing.toml")})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err = cmd.Execute()
	require.ErrorContains(t, err, "failed to load config file")
}
