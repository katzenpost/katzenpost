// SPDX-License-Identifier: AGPL-3.0-only

package config

type Notice struct {
	MinClientVersion string
	ClientNotice     string
}

func (n *Notice) validate() error {
	return nil
}
