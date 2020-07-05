# Copyright (C) 2020  David Stainton.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
module github.com/katzenpost/catshadow

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/agl/ed25519 v0.0.0-20200225211852-fd4d107ace12 // indirect
	github.com/katzenpost/client v0.0.4
	github.com/katzenpost/core v0.0.8
	github.com/katzenpost/doubleratchet v0.0.2
	github.com/katzenpost/memspool v0.0.2
	github.com/katzenpost/panda v0.0.4
	github.com/stretchr/testify v1.4.0
	github.com/ugorji/go/codec v1.1.7
	golang.org/x/crypto v0.0.0-20200427165652-729f1e841bcc
	gopkg.in/eapache/channels.v1 v1.1.0
	gopkg.in/op/go-logging.v1 v1.0.0-20160211212156-b2cb9fa56473
)
