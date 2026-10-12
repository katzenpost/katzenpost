// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"errors"

	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

const MOTDCapability = "motd"

func NewMOTD(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	return nil, errors.New("unimplemented")
}
