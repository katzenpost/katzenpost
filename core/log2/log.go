// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package log2

import "github.com/charmbracelet/log"

func ParseLevel(l string) log.Level {
	level, err := log.ParseLevel(l)
	if err != nil {
		panic(err)
	}
	return level
}
