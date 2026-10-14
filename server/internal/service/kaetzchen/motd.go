// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"fmt"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

const MOTDCapability = "motd"

type kaetzchenMOTD struct {
	log    *logging.Logger
	params Parameters
	text   []byte
}

func (k *kaetzchenMOTD) Capability() string {
	return MOTDCapability
}

func (k *kaetzchenMOTD) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenMOTD) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}
	k.log.Debugf("Handling request: %v", id)
	if _, err := pki.PrintableMOTD(k.text, pki.MaxMOTDLength); err != nil {
		return nil, err
	}
	return k.text, nil
}

func (k *kaetzchenMOTD) Halt() {}

func NewMOTD(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	text, ok := cfg.Config["Text"].(string)
	if !ok || text == "" {
		return nil, fmt.Errorf("kaetzchen/motd: Text must be a non-empty string")
	}
	if _, err := pki.PrintableMOTD([]byte(text), glue.Config().SphinxGeometry.UserForwardPayloadLength); err != nil {
		return nil, fmt.Errorf("kaetzchen/motd: Text: %w", err)
	}
	return &kaetzchenMOTD{
		log:    glue.LogBackend().GetLogger("kaetzchen/motd"),
		params: Parameters{ParameterEndpoint: cfg.Endpoint},
		text:   []byte(text),
	}, nil
}
