// session.go - mixnet client session
// Copyright (C) 2018  David Stainton.
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

package client

import (
	"fmt"

	"github.com/katzenpost/client/cborplugin"
)

func (s *Session) startPlugins() {
	eventBuilder := &cborplugin.EventBuilder{}
	for _, pluginConf := range s.cfg.CBORPlugin {
		args := []string{}
		if len(pluginConf.Config) > 0 {
			for key, val := range pluginConf.Config {
				args = append(args, fmt.Sprintf("-%s", key), val.(string))
			}
		}
		plugin := cborplugin.New(s.logBackend, eventBuilder)
		err := plugin.Start(pluginConf.Command, args)
		if err != nil {
			s.log.Fatal(err)
		}
	}
}
