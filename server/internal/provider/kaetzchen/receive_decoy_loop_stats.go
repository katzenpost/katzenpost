package kaetzchen

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

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

	stats := &loops.SphinxLoopStats{}
	err := cbor.Unmarshal(payload, &stats)
	if err != nil {
		k.log.Error("Invalid payload format, cannot decode loops.SphinxLoopStats CBOR object.")
		return nil, err
	}

	doc := k.glue.Provider().CurrentDocument()
	desc, err := doc.GetMixByKeyHash(stats.MixIdentityHash)
	if err != nil {
		k.log.Errorf("doc.GetMixByKeyHash failed")
		return nil, err
	}
	pubkey, err := desc.GetDecoyStatsKey()
	if err != nil {
		return nil, err
	}

	if !loops.Scheme.Verify(pubkey, stats.Payload, stats.Signature, nil) {
		k.log.Errorf("decoy stats failed signature verification")
		return nil, errors.New("decoy stats failed signature verification")
	}

	cachedStats := &loops.LoopStats{}
	err = cbor.Unmarshal(stats.Payload, &cachedStats)
	if err != nil {
		k.log.Error("Invalid payload format, cannot decode loops.LoopStats CBOR object.")
		return nil, err
	}

	err = k.glue.LoopsCache().Store(cachedStats, stats.Signature)
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
func NewStats(glue glue.Glue) (Kaetzchen, error) {
	k := &kaetzchenStats{
		log:    glue.LogBackend().GetLogger("kaetzchen/echo"),
		params: make(Parameters),
		glue:   glue,
	}
	k.params[ParameterEndpoint] = "+decoy_cache_stats"

	return k, nil
}
