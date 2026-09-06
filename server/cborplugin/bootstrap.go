// bootstrap.go - shared startup-failure reporting for cbor plugins
// Copyright (C) 2026  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cborplugin

import (
	"fmt"
	"os"
)

// FailStartup reports a plugin initialization failure and exits. Plugins
// must call this instead of panicking when they fail before completing the
// socket-path handshake, so the launching service node's captured stderr
// carries one clean, single-line reason instead of a multi-frame panic
// trace.
func FailStartup(component string, err error) {
	fmt.Fprintf(os.Stderr, "%s: failed to start: %v\n", component, err)
	os.Exit(1)
}
