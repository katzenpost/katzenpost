// SPDX-License-Identifier: AGPL-3.0-only

package config

import "github.com/katzenpost/katzenpost/core/pki"

type Notice struct {
	MinClientVersion string
	ClientNotice     string
}

func (n *Notice) validate() error {
	return pki.IsClientNoticeWellFormed(n.MinClientVersion, n.ClientNotice)
}
