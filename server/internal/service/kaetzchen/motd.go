// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"fmt"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

const (
	MOTDCapability = "motd"
	maxMOTDLength  = 512
)

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
	return k.text, nil
}

func (k *kaetzchenMOTD) Halt() {}

func NewMOTD(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	text, ok := cfg.Config["Text"].(string)
	if !ok || text == "" {
		return nil, fmt.Errorf("kaetzchen/motd: Text must be a non-empty string")
	}
	if len(text) > maxMOTDLength {
		return nil, fmt.Errorf("kaetzchen/motd: Text exceeds %d bytes", maxMOTDLength)
	}
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7e {
			return nil, fmt.Errorf("kaetzchen/motd: Text has a non-printable byte at %d", i)
		}
	}
	return &kaetzchenMOTD{
		log:    glue.LogBackend().GetLogger("kaetzchen/motd"),
		params: Parameters{ParameterEndpoint: cfg.Endpoint},
		text:   []byte(text),
	}, nil
}
