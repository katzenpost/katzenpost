// addr.go - Address validation and utilities.
// Copyright (C) 2017  Yawning Angel.
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

package utils

import (
	"fmt"
	"net"
)

// EnsureAddrIPPort returns nil iff the address is a raw IP + Port combination.
func EnsureAddrIPPort(a string) error {
	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return err
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("address '%v' is not an IP", host)
	}
	return nil
}
