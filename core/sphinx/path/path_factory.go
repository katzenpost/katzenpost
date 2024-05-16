package path

import (
	"errors"
	mRand "math/rand"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// PathFactory is used to compose Sphinx packet paths.
type PathFactory struct {
	rng *mRand.Rand
}

func NewPathFactory() *PathFactory {
	return &PathFactory{
		rng: rand.NewMath(),
	}
}

// ComposePath is used to compose a Sphinx packet path. Returns
// path and round trip time or an error.
func (d *PathFactory) ComposePath(
	geo *geo.Geometry,
	doc *pki.Document,
	srcMix *[32]byte,
	dstId []byte,
	dstMix *[32]byte,
	surbID *[constants.SURBIDLength]byte,
	baseTime time.Time,
	isForward bool) (outputPath []*PathHop, rtt time.Time, err error) {

	src, err := doc.GetGatewayByKeyHash(srcMix)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to find entry mix in pki doc")
	}
	dst, err := doc.GetServiceNodeByKeyHash(dstMix)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to find service mix in pki doc")
	}
	return New(d.rng, geo, doc, dstId, src, dst, surbID, baseTime, true, isForward)
}
