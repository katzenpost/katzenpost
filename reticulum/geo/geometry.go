// Package geo models the on-wire packet geometry of the Reticulum
// Network Stack.
//
// It is a parameterizable size calculator in the spirit of Katzenpost's
// core/sphinx/geo/geo.go: feed in the protocol's knobs (MTU, IFAC,
// truncated-hash length, ratchets) and read off every derived size
// (header, MDU, encrypted MDU, control-packet sizes, fragmentation
// behavior).
//
// This package concerns itself strictly with Reticulum itself.
// Application protocols built on top of Reticulum (LXMF, custom
// messaging, etc.) layer their own envelopes inside the encrypted DATA
// field; that's out of scope here.
//
// Reticulum wire format (RNS manual, "Wire Format" section):
//
//	[HEADER 2][IFAC 0..64][ADDRESSES 16/32][CONTEXT 1][DATA 0..N]
//
// For SINGLE destinations, DATA carries an encrypted Token:
//
//	[EPHEMERAL_PUBKEY 32][IV 16][CIPHERTEXT N*16][HMAC 32]
//
// For LINK destinations, the link's symmetric key is used directly and
// the ephemeral pubkey is omitted:
//
//	[IV 16][CIPHERTEXT N*16][HMAC 32]
//
// PLAIN destinations skip encryption entirely.
//
// All numbers below mirror the constants in RNS/Reticulum.py and
// RNS/Cryptography/Token.py from the reference implementation.
package geo

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// ----------------------------------------------------------------------------
// Reticulum protocol constants (authoritative — from the RNS spec & source).
// ----------------------------------------------------------------------------

const (
	// Carrier
	DefaultMTU = 500

	// Fixed wire header
	FlagsHopsLen = 2 // 1 flags byte + 1 hops byte
	ContextLen   = 1

	// Truncated SHA-256 destination hashes. Spec default 128 bits; the
	// spec also explicitly allows 256-bit addresses, so it's a knob.
	DefaultTruncHashLen = 16

	// IFAC (Interface Access Code) — Ed25519 sig, optionally truncated.
	// Spec: 8..512 bits.
	IFACMinBytes = 1
	IFACMaxBytes = 64

	// Token / per-packet AEAD (Reticulum's Fernet-like construction)
	EphPubkeyLen  = 32 // X25519 ephemeral public key (SINGLE only)
	TokenIVLen    = 16 // AES-CBC IV
	TokenHMACLen  = 32 // HMAC-SHA256
	TokenOverhead = TokenIVLen + TokenHMACLen // = 48
	AESBlock      = 16
	PKCS7MinPad   = 1
	PKCS7MaxPad   = 16

	// Identity & announces
	IDPubkeyLen    = 32 // X25519 enc pubkey
	IDSigkeyLen    = 32 // Ed25519 sig pubkey
	SignatureLen   = 64 // Ed25519 signature
	AnnNameHashLen = 10
	AnnRandHashLen = 10
	RatchetKeyLen  = 32 // X25519 ratchet pubkey, when enabled
)

// EncryptionMode describes how DATA is protected on the wire.
type EncryptionMode int

const (
	// EncryptionSingle: per-packet ECDH; eph_pubkey || iv || ct || hmac.
	EncryptionSingle EncryptionMode = iota
	// EncryptionLink: link symmetric key; iv || ct || hmac.
	EncryptionLink
	// EncryptionPlain: no encryption.
	EncryptionPlain
)

// String implements fmt.Stringer.
func (m EncryptionMode) String() string {
	switch m {
	case EncryptionSingle:
		return "SINGLE"
	case EncryptionLink:
		return "LINK"
	case EncryptionPlain:
		return "PLAIN"
	}
	return fmt.Sprintf("EncryptionMode(%d)", int(m))
}

// ----------------------------------------------------------------------------
// Geometry
// ----------------------------------------------------------------------------

// Geometry is a parameter set describing Reticulum's packet geometry.
//
// Configurable knobs (these are Reticulum's own knobs, nothing else):
//
//	MTU                wire MTU of the carrier
//	IFACEnabled        whether interface authentication is in use
//	IFACLen            IFAC byte length when enabled (1..64)
//	RatchetEnabled     whether announces include a 32-byte ratchet pubkey
//	TruncatedHashLen   destination hash length in bytes (16 or 32)
//
// Everything else is derived.
type Geometry struct {
	MTU              int
	IFACEnabled      bool
	IFACLen          int
	RatchetEnabled   bool
	TruncatedHashLen int
}

// New returns a Geometry initialised to the spec defaults.
func New() *Geometry {
	return &Geometry{
		MTU:              DefaultMTU,
		TruncatedHashLen: DefaultTruncHashLen,
	}
}

// Validate returns an error if the parameter set is not spec-conformant.
func (g *Geometry) Validate() error {
	if g.IFACEnabled && (g.IFACLen < IFACMinBytes || g.IFACLen > IFACMaxBytes) {
		return fmt.Errorf("ifac_len must be in [%d..%d] when IFAC enabled; got %d",
			IFACMinBytes, IFACMaxBytes, g.IFACLen)
	}
	if g.TruncatedHashLen != 16 && g.TruncatedHashLen != 32 {
		return errors.New("truncated_hash_len must be 16 or 32")
	}
	minMTU := FlagsHopsLen + 2*g.TruncatedHashLen + ContextLen
	if g.MTU < minMTU {
		return fmt.Errorf("mtu too small to carry HEADER_2 (need >= %d)", minMTU)
	}
	return nil
}

// IFACBytes returns the IFAC byte overhead (0 when disabled).
func (g *Geometry) IFACBytes() int {
	if g.IFACEnabled {
		return g.IFACLen
	}
	return 0
}

// HeaderBytes returns total RNS header overhead before the DATA field.
// HEADER_1 carries 1 destination hash; HEADER_2 (in-transport) carries 2.
func (g *Geometry) HeaderBytes(header2 bool) int {
	n := 1
	if header2 {
		n = 2
	}
	return FlagsHopsLen + g.IFACBytes() + n*g.TruncatedHashLen + ContextLen
}

// MDU is the max DATA-field bytes after the on-wire header.
//
// Reticulum's published MDU constant uses HEADER_2 (worst case), so
// callers who pass true match that.
func (g *Geometry) MDU(header2 bool) int {
	return g.MTU - g.HeaderBytes(header2)
}

// EncryptedMDU is the max plaintext bytes that fit in the DATA field for
// the given encryption mode.
//
// Mirrors RNS/Packet.py for SINGLE:
//
//	free = MDU - TOKEN_OVERHEAD - EPH_PUBKEY
//	mdu  = floor(free / AES_BLOCK) * AES_BLOCK - 1
//
// The "-1" reserves the minimum PKCS7 pad byte. LINK mode uses the same
// formula minus the per-packet ephemeral pubkey. PLAIN returns the raw
// DATA capacity.
func (g *Geometry) EncryptedMDU(mode EncryptionMode, header2 bool) int {
	if mode == EncryptionPlain {
		return g.MDU(header2)
	}
	free := g.MDU(header2) - TokenOverhead
	if mode == EncryptionSingle {
		free -= EphPubkeyLen
	}
	if free <= 0 {
		return 0
	}
	return (free/AESBlock)*AESBlock - 1
}

// OverheadBreakdown returns a map of every byte spent on protocol
// overhead before payload, for inspection.
func (g *Geometry) OverheadBreakdown(mode EncryptionMode, header2 bool) map[string]int {
	n := 1
	if header2 {
		n = 2
	}
	out := map[string]int{
		"flags+hops": FlagsHopsLen,
		"ifac":       g.IFACBytes(),
		"addresses":  n * g.TruncatedHashLen,
		"context":    ContextLen,
	}
	if mode == EncryptionSingle {
		out["eph_pubkey"] = EphPubkeyLen
	}
	if mode == EncryptionSingle || mode == EncryptionLink {
		out["aes_iv"] = TokenIVLen
		out["hmac"] = TokenHMACLen
		out["pkcs7_pad_min"] = PKCS7MinPad
	}
	return out
}

// OverheadTotal sums OverheadBreakdown.
func (g *Geometry) OverheadTotal(mode EncryptionMode, header2 bool) int {
	total := 0
	for _, v := range g.OverheadBreakdown(mode, header2) {
		total += v
	}
	return total
}

// ----- Well-known control packet sizes --------------------------------------
//
// Spec-quoted sizes (no IFAC, 16-byte hashes) for cross-checking:
//   Path Request    51   Announce        167
//   Link Request    83   Link Proof      115
//   Link RTT        99   Link Keepalive   20

// PathRequestSize returns the on-wire bytes of a path request packet.
func (g *Geometry) PathRequestSize() int {
	return g.HeaderBytes(false) + 2*g.TruncatedHashLen
}

// AnnounceSize returns the on-wire bytes of a destination announce.
// appDataLen is the length of optional application data carried inside.
func (g *Geometry) AnnounceSize(appDataLen int) int {
	body := IDPubkeyLen + IDSigkeyLen + AnnNameHashLen + AnnRandHashLen + SignatureLen + appDataLen
	if g.RatchetEnabled {
		body += RatchetKeyLen
	}
	return g.HeaderBytes(false) + body
}

// LinkRequestSize returns the on-wire bytes of a link request packet.
// Body is LKi: encryption pubkey (32) + signing pubkey (32).
func (g *Geometry) LinkRequestSize() int {
	return g.HeaderBytes(false) + IDPubkeyLen + IDSigkeyLen
}

// LinkProofSize returns the on-wire bytes of a link proof packet.
// Body is LKr (32) + Ed25519 signature (64).
func (g *Geometry) LinkProofSize() int {
	return g.HeaderBytes(false) + IDPubkeyLen + SignatureLen
}

// LinkRTTSize returns the on-wire bytes of an encrypted link RTT
// measurement packet. Body is iv + hmac + 2 AES blocks of ciphertext.
func (g *Geometry) LinkRTTSize() int {
	return g.HeaderBytes(false) + TokenIVLen + TokenHMACLen + 2*AESBlock
}

// LinkKeepaliveSize returns the on-wire bytes of an unencrypted
// 1-byte link keepalive packet.
func (g *Geometry) LinkKeepaliveSize() int {
	return g.HeaderBytes(false) + 1
}

// LinkSetupBytes returns the total per-hop on-wire bytes for the
// 3-packet Link establishment handshake (Link Request + Link Proof
// + Link RTT). For the default geometry this is 297 bytes.
func (g *Geometry) LinkSetupBytes() int {
	return g.LinkRequestSize() + g.LinkProofSize() + g.LinkRTTSize()
}

// BreakevenPackets returns the number of within-session packets at
// which LINK becomes more byte-efficient than SINGLE, amortizing
// the link setup cost.
//
// Each LINK packet saves EphPubkeyLen (32) bytes vs SINGLE by omitting
// the per-packet ephemeral pubkey, so breakeven is ceil(setup / 32).
// For the default geometry this is 10 packets. Below this threshold,
// SINGLE is cheaper; at or above it, LINK wins.
func (g *Geometry) BreakevenPackets() int {
	return int(math.Ceil(float64(g.LinkSetupBytes()) / float64(EphPubkeyLen)))
}

// ----- Multi-packet / Resource-style transfers ------------------------------
//
// Reticulum's Resource subsystem segments arbitrary-length data into
// packets at link MDU. The methods below model the sender-side packet
// count and total bytes; they ignore Resource's metadata/proof packets.

// FragmentsNeeded returns the number of fragment packets required to
// carry payloadLen bytes under the given encryption mode.
func (g *Geometry) FragmentsNeeded(payloadLen int, mode EncryptionMode, header2 bool) int {
	per := g.EncryptedMDU(mode, header2)
	if per <= 0 {
		return 0
	}
	return int(math.Ceil(float64(payloadLen) / float64(per)))
}

// fragmentWireBytes returns the on-wire bytes for a single fragment
// carrying `plain` bytes of plaintext under the given mode.
//
// Note: a fragment at maximum plaintext (per = EncryptedMDU) encodes to
// MTU-1 bytes, not MTU — because EncryptedMDU's "-1" reserves room for
// one mandatory PKCS7 pad byte.
func (g *Geometry) fragmentWireBytes(plain int, mode EncryptionMode, header2 bool) int {
	if mode == EncryptionPlain {
		return g.HeaderBytes(header2) + plain
	}
	fixed := g.HeaderBytes(header2) + TokenIVLen + TokenHMACLen
	if mode == EncryptionSingle {
		fixed += EphPubkeyLen
	}
	ct := int(math.Ceil(float64(plain+PKCS7MinPad)/float64(AESBlock))) * AESBlock
	return fixed + ct
}

// TotalWireBytes returns the sum of on-wire bytes for an N-byte payload
// split into fragments. Each fragment is sized accurately for its
// plaintext content.
func (g *Geometry) TotalWireBytes(payloadLen int, mode EncryptionMode, header2 bool) int {
	per := g.EncryptedMDU(mode, header2)
	if per <= 0 || payloadLen <= 0 {
		return 0
	}
	n := int(math.Ceil(float64(payloadLen) / float64(per)))
	full := n - 1
	tail := payloadLen - full*per
	return full*g.fragmentWireBytes(per, mode, header2) +
		g.fragmentWireBytes(tail, mode, header2)
}

// OverheadRatio returns (wireBytes - payloadBytes) / payloadBytes.
// For payloadLen <= 0 it returns +Inf.
func (g *Geometry) OverheadRatio(payloadLen int, mode EncryptionMode, header2 bool) float64 {
	if payloadLen <= 0 {
		return math.Inf(1)
	}
	wire := g.TotalWireBytes(payloadLen, mode, header2)
	return float64(wire-payloadLen) / float64(payloadLen)
}

// ----- Presentation ---------------------------------------------------------

type sumRow struct {
	label string
	val   int
}

// Summary returns a human-readable size table.
func (g *Geometry) Summary() string {
	rows := []sumRow{
		{"MTU", g.MTU},
		{"Truncated hash length", g.TruncatedHashLen},
		{"IFAC bytes", g.IFACBytes()},
		{"Header HEADER_1", g.HeaderBytes(false)},
		{"Header HEADER_2", g.HeaderBytes(true)},
		{"MDU (HEADER_2)", g.MDU(true)},
		{"Encrypted MDU, SINGLE, H2", g.EncryptedMDU(EncryptionSingle, true)},
		{"Encrypted MDU, LINK,   H2", g.EncryptedMDU(EncryptionLink, true)},
		{"Encrypted MDU, PLAIN,  H2", g.EncryptedMDU(EncryptionPlain, true)},
		{"Path request size", g.PathRequestSize()},
		{"Announce size (no app_data)", g.AnnounceSize(0)},
		{"Link request size", g.LinkRequestSize()},
		{"Link proof size", g.LinkProofSize()},
		{"Link RTT size", g.LinkRTTSize()},
		{"Link keepalive size", g.LinkKeepaliveSize()},
		{"Link setup bytes (per-hop)", g.LinkSetupBytes()},
		{"Breakeven packets (LINK vs SINGLE)", g.BreakevenPackets()},
	}
	w := 0
	for _, r := range rows {
		if len(r.label) > w {
			w = len(r.label)
		}
	}
	var b strings.Builder
	b.WriteString("Reticulum Geometry\n")
	b.WriteString(strings.Repeat("-", w+14))
	b.WriteByte('\n')
	for _, r := range rows {
		fmt.Fprintf(&b, "%-*s : %d bytes\n", w, r.label, r.val)
	}
	return b.String()
}

// String implements fmt.Stringer.
func (g *Geometry) String() string {
	return g.Summary()
}

// ----- Preset configurations ------------------------------------------------

// Default returns the spec defaults: 500-byte MTU, no IFAC, 128-bit
// addresses.
func Default() *Geometry { return New() }

// LoRaNamedNetwork returns a Geometry for a LoRa carrier with an
// 8-byte (64-bit) IFAC — typical for a named virtual network.
func LoRaNamedNetwork() *Geometry {
	g := New()
	g.IFACEnabled = true
	g.IFACLen = 8
	return g
}

// LoRaAuthenticated returns a Geometry for a LoRa carrier with a full
// 64-byte (512-bit) IFAC — passphrase-authenticated network.
func LoRaAuthenticated() *Geometry {
	g := New()
	g.IFACEnabled = true
	g.IFACLen = 64
	return g
}

// ----------------------------------------------------------------------------
// Multi-hop paths
// ----------------------------------------------------------------------------
//
// Reticulum runs over heterogeneous interfaces. The global RNS.Reticulum.MTU
// (500 B) is the universal baseline — what every peer must support and what
// non-Link traffic always uses. But individual interfaces can have higher
// MTUs (TCP, AutoInterface, fast radios), and Link MTU Discovery (RNS 0.9.0+)
// upgrades a Link's MTU to min(interface_MTU) along its path.
//
// IFAC is per-hop, not per-packet: the packet body is identical on every
// hop, but each hop adds (and verifies) its own IFAC signature. The sender
// must size the body to fit the bottleneck: min over hops of (MTU - IFAC).

// Hop describes one hop along a Reticulum path: an interface with its
// own wire MTU and optional IFAC overhead.
type Hop struct {
	Name         string // optional, for display
	InterfaceMTU int
	IFACEnabled  bool
	IFACLen      int
}

// IFACBytes returns the per-packet IFAC overhead this hop adds.
func (h Hop) IFACBytes() int {
	if h.IFACEnabled {
		return h.IFACLen
	}
	return 0
}

// AvailableBody returns the byte budget for the packet body
// (RNS header + addresses + context + DATA, excluding IFAC) on this hop.
func (h Hop) AvailableBody() int {
	return h.InterfaceMTU - h.IFACBytes()
}

// Path is an ordered sequence of Hops between sender and recipient.
type Path struct {
	Hops             []Hop
	TruncatedHashLen int
}

// NewPath returns a Path with the default truncated hash length and
// the given hops.
func NewPath(hops ...Hop) *Path {
	return &Path{
		Hops:             hops,
		TruncatedHashLen: DefaultTruncHashLen,
	}
}

// EffectiveBodyMTU returns the bottleneck capacity for a packet body
// (excluding IFAC) — this is what Link MTU Discovery converges to:
// min over hops of (interface_MTU - IFAC).
// Returns DefaultMTU for an empty path.
func (p *Path) EffectiveBodyMTU() int {
	if len(p.Hops) == 0 {
		return DefaultMTU
	}
	m := p.Hops[0].AvailableBody()
	for _, h := range p.Hops[1:] {
		if a := h.AvailableBody(); a < m {
			m = a
		}
	}
	return m
}

// LinkGeometry returns the Geometry a Link sees end-to-end after MTU
// discovery converges along this path. The MTU is the bottleneck body
// MTU; IFAC is 0 because per-hop IFAC overhead has already been
// deducted (each hop adds its own at transmission).
func (p *Path) LinkGeometry() *Geometry {
	return &Geometry{
		MTU:              p.EffectiveBodyMTU(),
		TruncatedHashLen: p.TruncatedHashLen,
	}
}

// BaselineGeometry returns the Geometry used for non-Link packets,
// which always use the universal DefaultMTU baseline rather than any
// path-discovered upgrade.
func (p *Path) BaselineGeometry() *Geometry {
	return &Geometry{
		MTU:              DefaultMTU,
		TruncatedHashLen: p.TruncatedHashLen,
	}
}

// HopWireBytes returns the per-hop on-wire byte totals for moving
// payloadLen plaintext bytes via a Link along this path. Each entry is
// (sum of fragment bodies) + (fragment count * hop_IFAC).
func (p *Path) HopWireBytes(payloadLen int, mode EncryptionMode, header2 bool) []int {
	g := p.LinkGeometry()
	bodyTotal := g.TotalWireBytes(payloadLen, mode, header2)
	n := g.FragmentsNeeded(payloadLen, mode, header2)
	out := make([]int, len(p.Hops))
	for i, h := range p.Hops {
		out[i] = bodyTotal + n*h.IFACBytes()
	}
	return out
}

// TotalCarrierBytes returns the sum of on-wire bytes across every hop —
// the total airtime / link cost of moving payloadLen bytes through
// the entire path.
func (p *Path) TotalCarrierBytes(payloadLen int, mode EncryptionMode, header2 bool) int {
	g := p.LinkGeometry()
	bodyTotal := g.TotalWireBytes(payloadLen, mode, header2)
	if len(p.Hops) == 0 {
		return bodyTotal
	}
	n := g.FragmentsNeeded(payloadLen, mode, header2)
	sumIFAC := 0
	for _, h := range p.Hops {
		sumIFAC += h.IFACBytes()
	}
	return len(p.Hops)*bodyTotal + n*sumIFAC
}

// LinkSetupCarrierBytes returns the total airtime cost across every
// hop of establishing a Link along this path. Each of the 3 setup
// packets (Link Request, Link Proof, Link RTT) traverses every hop
// and accumulates per-hop IFAC overhead.
//
// Setup packets always use the universal 500-byte baseline geometry,
// not any path-discovered link MTU — they're what bootstraps the link
// in the first place.
func (p *Path) LinkSetupCarrierBytes() int {
	perHop := p.BaselineGeometry().LinkSetupBytes()
	if len(p.Hops) == 0 {
		return perHop
	}
	sumIFAC := 0
	for _, h := range p.Hops {
		sumIFAC += h.IFACBytes()
	}
	const setupPackets = 3
	return len(p.Hops)*perHop + setupPackets*sumIFAC
}

// ----------------------------------------------------------------------------
// Round-trip operations
// ----------------------------------------------------------------------------
//
// Pigeonhole-style protocols (and many others built on Reticulum) are
// fundamentally request/response: the client sends a query, the server
// returns a response. Sizing one of these operations end-to-end requires
// summing both directions across every hop. Query and QueryCost express
// this directly.

// Query describes a single request/response operation in plaintext
// bytes (i.e., the application-level sizes before any RNS or transport
// overhead is added).
type Query struct {
	RequestBytes  int
	ResponseBytes int
}

// QueryCost is the resolved on-wire cost of a Query across a Path.
//
// All byte counts are end-to-end carrier totals (summed across every
// hop) and account for header overhead, encryption overhead,
// fragmentation padding, and per-hop IFAC. They do NOT include Link
// establishment cost; sum Path.LinkSetupCarrierBytes() yourself when
// modeling the cost of a cold first query versus warm follow-ups.
type QueryCost struct {
	RequestWireBytes  int   // carrier bytes for the request, all hops
	ResponseWireBytes int   // carrier bytes for the response, all hops
	TotalWireBytes    int   // request + response
	RequestFragments  int   // packets needed for the request body
	ResponseFragments int   // packets needed for the response body
	PerHopWireBytes   []int // request + response carrier bytes, per hop
}

// WireCost returns the on-wire cost of executing this query as a
// single round trip across the given path under the given encryption
// mode. Link setup is not included; for the cost of a cold first
// query, add Path.LinkSetupCarrierBytes() to TotalWireBytes.
func (q Query) WireCost(p *Path, mode EncryptionMode) QueryCost {
	const header2 = true
	g := p.LinkGeometry()

	reqTotal := p.TotalCarrierBytes(q.RequestBytes, mode, header2)
	resTotal := p.TotalCarrierBytes(q.ResponseBytes, mode, header2)

	var perHop []int
	if len(p.Hops) > 0 {
		reqHop := p.HopWireBytes(q.RequestBytes, mode, header2)
		resHop := p.HopWireBytes(q.ResponseBytes, mode, header2)
		perHop = make([]int, len(p.Hops))
		for i := range p.Hops {
			perHop[i] = reqHop[i] + resHop[i]
		}
	}

	return QueryCost{
		RequestWireBytes:  reqTotal,
		ResponseWireBytes: resTotal,
		TotalWireBytes:    reqTotal + resTotal,
		RequestFragments:  g.FragmentsNeeded(q.RequestBytes, mode, header2),
		ResponseFragments: g.FragmentsNeeded(q.ResponseBytes, mode, header2),
		PerHopWireBytes:   perHop,
	}
}

// BreakevenQueries returns the number of queries at which using a Link
// becomes cheaper than addressing each query as SINGLE, accounting for
// the Link setup cost on the given path.
//
// Returns 0 if LINK is cheaper from the first query (e.g., when the
// per-fragment savings outweigh setup), and -1 if SINGLE is always at
// least as cheap (the path or query shape provides no per-query
// savings — typically tiny one-fragment queries on a no-IFAC path
// where the 32-byte ephemeral pubkey is the only difference).
func (q Query) BreakevenQueries(p *Path) int {
	singleCost := q.WireCost(p, EncryptionSingle).TotalWireBytes
	linkCost := q.WireCost(p, EncryptionLink).TotalWireBytes
	saving := singleCost - linkCost
	if saving <= 0 {
		return -1
	}
	setup := p.LinkSetupCarrierBytes()
	if setup <= 0 {
		return 0
	}
	return int(math.Ceil(float64(setup) / float64(saving)))
}
