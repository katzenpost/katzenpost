package path

import (
	"errors"
	mRand "math/rand"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type PathFactory interface {
	ComposePath(
		geo *geo.Geometry,
		doc *pki.Document,
		srcMix *[32]byte,
		dstId []byte,
		dstMix *[32]byte,
		surbID *[constants.SURBIDLength]byte,
		baseTime time.Time,
		isForward bool) (outputPath []*PathHop, rtt time.Time, err error)
}

// DefaultPathFactory is used to compose Sphinx packet paths.
type DefaultPathFactory struct {
	rng *mRand.Rand
}

func NewDefaultPathFactory() *DefaultPathFactory {
	return &DefaultPathFactory{
		rng: rand.NewMath(),
	}
}

// ComposePath is used to compose a Sphinx packet path. Returns
// path and round trip time or an error.
func (d *DefaultPathFactory) ComposePath(
	geo *geo.Geometry,
	doc *pki.Document,
	srcMix *[32]byte,
	dstId []byte,
	dstMix *[32]byte,
	surbID *[constants.SURBIDLength]byte,
	baseTime time.Time,
	isForward bool) (outputPath []*PathHop, rtt time.Time, err error) {

	src, err := doc.GetProviderByKeyHash(srcMix)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to find entry mix in pki doc")
	}
	dst, err := doc.GetProviderByKeyHash(dstMix)
	if err != nil {
		return nil, time.Time{}, errors.New("failed to find service mix in pki doc")
	}
	return New(d.rng, geo, doc, dstId, src, dst, surbID, baseTime, true, isForward)
}
