// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build wasm

package transport

import "errors"

func (c *UnixListenConfig) listen([]Listener) (Listener, error) {
	return nil, errors.New("not implemented")
}
