// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package tomlstrict provides an opt-in strict TOML check: it decodes a
// configuration file and reports any key present in the file that does
// not map to a field of the target Config struct.
//
// The component config loaders decode with BurntSushi's lenient
// toml.Unmarshal, which silently ignores unknown keys so that a routine
// binary upgrade never bricks a node over a stray line. That leniency
// is the wrong default at validation time, where a stale or misspelled
// key is precisely what the operator wants to be told about. This
// package is the strict counterpart, used by the daemons'
// --validate-only path and by the kpconfig umbrella validator, not on
// the normal startup path.
//
// It has no katzenpost imports by design, so it can be used from any
// command without risking an import cycle with the config packages.
package tomlstrict

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Check decodes the TOML file at path into cfg (a fresh pointer to the
// component's Config struct) and returns an error enumerating every key
// in the file that the struct does not model. A nil error means every
// key in the file was understood.
//
// cfg is mutated by the decode and is intended to be a throwaway
// instance: callers that also need a validated config should obtain it
// from the component's own LoadFile, which additionally runs
// FixupAndValidate. Check answers only the orthogonal question "does
// this file contain anything the schema does not recognise?".
func Check(path string, cfg interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	md, err := toml.NewDecoder(bytes.NewReader(b)).Decode(cfg)
	if err != nil {
		return err
	}
	undecoded := md.Undecoded()
	if len(undecoded) == 0 {
		return nil
	}

	// An array of tables repeats each leaf key once per element, so the
	// raw list is noisy. Collapse to the distinct dotted key paths.
	seen := make(map[string]struct{}, len(undecoded))
	keys := make([]string, 0, len(undecoded))
	for _, k := range undecoded {
		s := k.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		keys = append(keys, s)
	}
	sort.Strings(keys)
	return fmt.Errorf("unrecognised configuration keys: %s", strings.Join(keys, ", "))
}
