// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package main

import "os"

func notifyReload(chan os.Signal) {}
