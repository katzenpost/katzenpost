package kaetzchen

import (
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"gopkg.in/op/go-logging.v1"
)

// StatsCapability is the standardized capability for the echo service.
const StatsCapability = "stats"

type kaetzchenStats struct {
	log *logging.Logger

	params Parameters
}

func (k *kaetzchenStats) Capability() string {
	return StatsCapability
}

func (k *kaetzchenStats) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenStats) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	if !hasSURB {
		return nil, ErrNoResponse
	}

	k.log.Debugf("Handling request: %v", id)
	return payload, nil
}

func (k *kaetzchenStats) Halt() {
	// No termination required.
}

// NewStats constructs a new Stats Kaetzchen instance, providing the "echo"
// capability, on the configured endpoint.
func NewStats(cfg *config.Kaetzchen, glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenStats{
		log:    glue.LogBackend().GetLogger("kaetzchen/echo"),
		params: make(Parameters),
	}
	k.params[ParameterEndpoint] = cfg.Endpoint

	return k, nil
}
