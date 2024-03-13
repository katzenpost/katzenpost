package kaetzchen

import (
	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/loops"
)

// StatsCapability is the standardized capability for the echo service.
const StatsCapability = "stats"

type kaetzchenStats struct {
	log    *logging.Logger
	params Parameters
	glue   glue.Glue
}

func (k *kaetzchenStats) Capability() string {
	return StatsCapability
}

func (k *kaetzchenStats) Parameters() Parameters {
	return k.params
}

func (k *kaetzchenStats) OnRequest(id uint64, payload []byte, hasSURB bool) ([]byte, error) {
	k.log.Debugf("Handling request: %v", id)

	stats := &loops.LoopStats{}
	err := cbor.Unmarshal(payload, &stats)
	if err != nil {
		k.log.Error("Invalid payload format, cannot decoy LoopStats CBOR object.")
		return nil, err
	}

	k.log.Noticef("Storing received LoopStats for %d loops", len(stats.Stats))

	err = k.glue.LoopsCache().Store(stats)
	if err != nil {
		k.log.Errorf("failed to store decoy loop stats cache: %s", err)
		return nil, err
	}

	// success, no reply
	return nil, nil
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
		glue:   glue,
	}
	k.params[ParameterEndpoint] = cfg.Endpoint

	return k, nil
}
