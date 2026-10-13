// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"strings"

	"github.com/carlmjohnson/versioninfo"
)

// Version returns the build's version string for logging and CLI
// display: the module version with any "+dirty" suffix stripped,
// followed by the full VCS revision when one was stamped. Dirty
// markers are deliberately omitted: they say only that the build tree
// had local modifications, which identifies no reproducible source
// state.
func Version() string {
	return resolveVersion(BuildVersion, versioninfo.Version, versioninfo.Revision)
}

var BuildVersion string

func resolveVersion(build, version, revision string) string {
	return formatVersion(version, revision)
}

func formatVersion(version, revision string) string {
	v := strings.TrimSuffix(version, "+dirty")
	if revision != "" && revision != "unknown" {
		return v + " rev " + revision
	}
	return v
}
