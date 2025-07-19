// SPDX-FileCopyrightText: Copyright (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"strings"
)

// TruncatePEMForLogging truncates a PEM string to first two lines plus "..."
// This is useful for logging PEM keys in a more concise format while preserving
// the header and first line of data for debugging purposes.
func TruncatePEMForLogging(pemStr string) string {
	lines := strings.Split(strings.TrimSpace(pemStr), "\n")
	if len(lines) <= 2 {
		return pemStr
	}
	return strings.Join(lines[:2], "\n") + "\n..."
}
