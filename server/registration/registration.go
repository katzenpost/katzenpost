// registration.go - Provider registration protocol constants
// Copyright (C) 2018  David Stainton
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

// Package provides registration protocol constants
package registration

const (
	URLBase = "/registration"
	Version = "0"

	// form fields
	VersionField     = "version"
	CommandField     = "command"
	UserField        = "user"
	LinkKeyField     = "link_key"
	IdentityKeyField = "identity_key"

	// registration types
	RegisterLinkCommand            = "register_link_key"
	RegisterLinkAndIdentityCommand = "register_link_and_identity_key"
)
