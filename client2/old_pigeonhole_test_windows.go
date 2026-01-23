// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package client2

import (
	"testing"
)

func TestCreateChannelWriteRequest(t *testing.T) {
	t.Skip("Skipping pigeonhole tests on Windows due to cryptographic scheme availability issues")
}

func TestCreateChannelWriteRequestPayloadTooLarge(t *testing.T) {
	t.Skip("Skipping pigeonhole tests on Windows due to cryptographic scheme availability issues")
}
