// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func dialFakeDaemon(t *testing.T) (*ThinClient, net.Conn) {
	client, server := net.Pipe()
	tc := newHandshakeTestClient(t, client)
	served := make(chan struct{})
	go func() {
		defer close(served)
		sendResponse(t, server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected: true, SphinxGeometry: tc.sphinxGeo, PigeonholeGeometry: tc.pigeonGeo,
			},
		})
		sendResponse(t, server, pkiDocResponse(t, 400))
		if _, err := readRequest(server); err != nil {
			return
		}
		sendResponse(t, server, &Response{SessionTokenReply: &SessionTokenReply{}})
	}()
	require.NoError(t, tc.Dial())
	<-served
	t.Cleanup(func() {
		tc.Disconnect()
		server.Close()
	})
	return tc, server
}

func serveOneReply(t *testing.T, server net.Conn, reply func(*Request) *Response) {
	go func() {
		req, err := readRequest(server)
		if err != nil {
			return
		}
		sendResponse(t, server, reply(req))
	}()
}

func TestGeometryGettersReturnWhatTheDaemonSupplied(t *testing.T) {
	tc, _ := dialFakeDaemon(t)
	require.Equal(t, tc.sphinxGeo, tc.GetSphinxGeometry())
	require.Equal(t, tc.pigeonGeo, tc.GetPigeonholeGeometry())
}

func TestVoucherMintReturnsTheDaemonReply(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{VoucherMintReply: &VoucherMintReply{
			QueryID: req.VoucherMint.QueryID,
			Voucher: []byte("voucher"),
		}}
	})
	reply, err := tc.VoucherMint([]byte("write cap"), "alice")
	require.NoError(t, err)
	require.Equal(t, []byte("voucher"), reply.Voucher)
}

func TestVoucherMintReportsAnErrorCode(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{VoucherMintReply: &VoucherMintReply{
			QueryID: req.VoucherMint.QueryID, ErrorCode: 1,
		}}
	})
	reply, err := tc.VoucherMint([]byte("write cap"), "alice")
	require.Error(t, err)
	require.Nil(t, reply)
}

func TestVoucherInductReturnsTheDaemonReply(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{VoucherInductReply: &VoucherInductReply{
			QueryID: req.VoucherInduct.QueryID, SealedReply: []byte("sealed"),
		}}
	})
	reply, err := tc.VoucherInduct([]byte("voucher"), []byte("payload"), []byte("who"))
	require.NoError(t, err)
	require.Equal(t, []byte("sealed"), reply.SealedReply)
}

func TestVoucherOpenReturnsTheDaemonReply(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{VoucherOpenReply: &VoucherOpenReply{
			QueryID: req.VoucherOpen.QueryID, WhoReply: []byte("who"),
		}}
	})
	reply, err := tc.VoucherOpen([]byte("secret"), []byte("sealed"), []byte("write cap"))
	require.NoError(t, err)
	require.Equal(t, []byte("who"), reply.WhoReply)
}

func TestVoucherDeriveStreamReturnsTheDaemonReply(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{VoucherDeriveStreamReply: &VoucherDeriveStreamReply{
			QueryID: req.VoucherDeriveStream.QueryID, VoucherReadCap: []byte("read cap"),
		}}
	})
	reply, err := tc.VoucherDeriveStream([]byte("voucher"))
	require.NoError(t, err)
	require.Equal(t, []byte("read cap"), reply.VoucherReadCap)
}

func TestGetPKIDocumentRawReturnsThePayloadAndEpoch(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{GetPKIDocumentReply: &GetPKIDocumentReply{
			QueryID: req.GetPKIDocument.QueryID, Payload: []byte("document"), Epoch: 401,
		}}
	})
	payload, epoch, err := tc.GetPKIDocumentRaw(401)
	require.NoError(t, err)
	require.Equal(t, []byte("document"), payload)
	require.Equal(t, uint64(401), epoch)
}

func TestGetDirectoryAuthoritiesReturnsTheDaemonList(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{GetDirectoryAuthoritiesReply: &GetDirectoryAuthoritiesReply{
			QueryID:     req.GetDirectoryAuthorities.QueryID,
			Authorities: []*DirectoryAuthority{{Identifier: "auth1"}},
		}}
	})
	authorities, err := tc.GetDirectoryAuthorities()
	require.NoError(t, err)
	require.Len(t, authorities, 1)
	require.Equal(t, "auth1", authorities[0].Identifier)
}

func TestGetMessageBoxIndexCounterReturnsTheCounter(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{GetMessageBoxIndexCounterReply: &GetMessageBoxIndexCounterReply{
			QueryID: req.GetMessageBoxIndexCounter.QueryID, Counter: 7,
		}}
	})
	counter, err := tc.GetMessageBoxIndexCounter(newTestMessageBoxIndex(t))
	require.NoError(t, err)
	require.Equal(t, uint64(7), counter)
}

func TestGetMessageBoxIndexCounterRejectsANilIndex(t *testing.T) {
	tc, _ := dialFakeDaemon(t)
	_, err := tc.GetMessageBoxIndexCounter(nil)
	require.Error(t, err)
}

func TestCreateCourierEnvelopesFromTombstoneRangeReturnsTheEnvelopes(t *testing.T) {
	tc, server := dialFakeDaemon(t)
	serveOneReply(t, server, func(req *Request) *Response {
		return &Response{CreateCourierEnvelopesFromTombstoneRangeReply: &CreateCourierEnvelopesFromTombstoneRangeReply{
			QueryID:   req.CreateCourierEnvelopesFromTombstoneRange.QueryID,
			Envelopes: [][]byte{[]byte("envelope")},
			Buffer:    []byte("rest"),
		}}
	})
	envelopes, buffer, _, err := tc.CreateCourierEnvelopesFromTombstoneRange(
		newTestWriteCap(t), newTestMessageBoxIndex(t), 1, true, true, []byte("payload"))
	require.NoError(t, err)
	require.Len(t, envelopes, 1)
	require.Equal(t, []byte("rest"), buffer)
}

func TestCreateCourierEnvelopesFromTombstoneRangeRejectsNilArguments(t *testing.T) {
	tc, _ := dialFakeDaemon(t)
	_, _, _, err := tc.CreateCourierEnvelopesFromTombstoneRange(nil, newTestMessageBoxIndex(t), 1, true, true, nil)
	require.Error(t, err)
	_, _, _, err = tc.CreateCourierEnvelopesFromTombstoneRange(newTestWriteCap(t), nil, 1, true, true, nil)
	require.Error(t, err)
}
