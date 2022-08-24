// crypto_test.go - Cryptographic primitive tests.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	ctidh "git.xx.network/elixxir/ctidh_cgo"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	assert := assert.New(t)

	var src [1024]byte
	_, err := rand.Read(src[:])
	require.NoError(t, err, "failed to read source buffer")

	expected := sha512.Sum512_256(src[:])
	actual := Hash(src[:])
	assert.Equal(HashLength, len(actual), "Hash() returned unexpected size digest")
	assert.Equal(expected, actual, "Hash() mismatch against SHA512-256")
}

func TestVectorHash(t *testing.T) {
	assert := assert.New(t)
	mesg, err := hex.DecodeString("f72fbd7f19e0f192524aea4973354479d6507d964242b30ded31c87e81c5c889")
	assert.NoError(err)
	hash := Hash(mesg)
	want, err := hex.DecodeString("9b931e466dc077f2cdf57784996dd19006a60e411692a8bdca4882c129c03a86")
	assert.NoError(err)
	assert.Equal(hash[:], want)
}

func TestMAC(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var key [MACKeyLength]byte
	_, err := rand.Read(key[:])
	require.NoError(err, "failed to read MAC key")

	var src [1024]byte
	_, err = rand.Read(src[:])
	require.NoError(err, "failed to read source buffer")

	eM := hmac.New(sha256.New, key[:])
	eM.Write(src[:])
	expected := eM.Sum(nil)
	expected = expected[:MACLength]

	m := NewMAC(&key)
	n, err := m.Write(src[:])
	assert.Equal(len(src), n, "Write() returned unexpected length")
	assert.NoError(err, "failed to write MAC data")
	actual := m.Sum(nil)
	assert.Equal(expected, actual, "Sum() mismatch against HMAC-SHA256-128")

	prefix := []byte("Append Test Prefix")
	expected = append(prefix, expected...)
	actual = m.Sum(prefix)
	assert.Equal(expected, actual, "Sum(prefix) mismatch against HMAC-SHA256-128")

	m.Reset()
	actual = m.Sum(nil)
	assert.NotEqual(expected, actual, "Reset() did not appear to clear state")
}

func TestVectorMAC(t *testing.T) {
	assert := assert.New(t)

	var key [MACKeyLength]byte
	_, err := rand.Read(key[:])
	assert.NoError(err, "failed to read MAC key")

	var src [256]byte
	_, err = rand.Read(src[:])
	assert.NoError(err, "failed to read source buffer")

	m := NewMAC(&key)
	macLen, err := m.Write(src[:])
	assert.NoError(err)
	assert.Equal(len(src), macLen)
	actual := m.Sum(nil)

	t.Logf("key %x src %x output %x", key[:], src[:], actual)
}

func TestStream(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var key [StreamKeyLength]byte
	_, err := rand.Read(key[:])
	require.NoError(err, "failed to read Stream key")

	var iv [StreamIVLength]byte
	_, err = rand.Read(iv[:])
	require.NoError(err, "failed to read Stream IV")

	s := NewStream(&key, &iv)

	var expected, actual [1024]byte
	blk, err := aes.NewCipher(key[:])
	require.NoError(err, "failed to initialize crypto/aes")
	ctr := cipher.NewCTR(blk, iv[:])

	ctr.XORKeyStream(expected[:], expected[:])
	s.KeyStream(actual[:])
	assert.Equal(expected, actual, "KeyStream() mismatch against CTR-AES128")

	ctr.XORKeyStream(expected[:], expected[:])
	s.XORKeyStream(actual[:], actual[:])
	assert.Equal(expected, actual, "XORKeyStream() mismatch against CTR-AES128")

	s.Reset()
}

func TestVectorStream(t *testing.T) {
	require := require.New(t)

	var key [StreamKeyLength]byte
	rawKey, err := hex.DecodeString("053ac00139e7bbd473953a6c310e26b6")
	require.NoError(err, "failed to read Stream key")
	copy(key[:], rawKey)

	var iv [StreamIVLength]byte
	rawIv, err := hex.DecodeString("ff03c942f5c95a5eca94b1047a6e327e")
	require.NoError(err, "failed to read Stream IV")
	copy(iv[:], rawIv)

	s := NewStream(&key, &iv)
	var expected, actual [1024]byte
	s.KeyStream(actual[:])
	rawExpected1, err := hex.DecodeString("ee67d27a5853ae79bc0b7fae1bdfccfa2b3f01fb7d86287606a46ca5e580655cb8078db09e79fc2f6bf2a70c3baee04c72870aea12a3a8689b8ce32f1a370405e497df8a9d4df19bb793149dfbac4e1daeff4093c760f5d2a2733cee176f39957a0cafb1abb912cfaa610571fa234a01b79d73c23eea88f0e9d29603e7dfbe2708d8dbb162871b5b2a6cecb2ff6159f6b02bb7b3bb8f20e950f81bf53be772b9654cdb7084c924d09d15d1fda1206f21e2dc0d8012faa6761396c2b81b1d772b6b12a8249cf57bfc1be9471c9b5a9445c06662f3877578b7ffb91c18fa67fdcf62643ed0923f432760c36ca4a145f8e955fb4e04ef491dd274f436986bf3e2fa784f8c7a819d083f3b85e916edf0399d13168357ffcc15902eda24dfbcacd1a75765c1cae161c464851d1d8dfdb5ca302b0afcbb2968ec795a9c51738e3d71737f494d337a662be6e5c35b696b1523c3d0f5c2bddc8074c27a0c4a19e41d55a3d9093d6f5f77b804536b82e815e7dd9433e5cb0269ae71087d0b76b883c09728d089433a07a078944054943afc66e72a9bcd4993346ab5a676ca52e25ff0efd21643b65b69285719551a3d8d74b324ccaf7e3df43cac63fb5f1b1f5f8b3b89f9897c0e798f5b1c6f00e3558afb1b48763a2274709b59b856eae1cc27e4bddff635a24b00e2d074b0e9bef9933e8988dd6db2512e259aecf6e2c8979468375372ff87a3b6414aaa2d40c2db24fb13ee6687b5d6573a9d029cd37b2a151c392a99068d67d5e4ca46610b2e12da4ca1dd52eb8fa25bccea462c02a6f20a2a6e719f056685cacbf82af7f60018b4bdb94b22ea682956d062141220bed5d0d3e857864dd5903585e5374c766077d4f3f1e8347ee5263966b267497e8437617d0890631c37d7484890055a0279d01a280db37fb9c7f6b034cf979f49a93291b7599b1a6f91a9236857a8e313e6851e0c9cc7ecf03409b3adb825e9cb999b100af2a3f0b0202d89491346f5aa075478d4db9ebf0d15b43ec3a982d1d855251118a675b01c752ebe18c6642302c8b28cb4def2a897abdd5673fc9305c42deb610825f49155a81eb9bcb4813ad06ed66f4af79fd5184a7d650bea4cbde9069e21361376deae3a92a6828bc0349b78519f7237459f29aaf8c9b5b38c0b554e45e2dd8f89b6c1923b58d1103f5a33542759b746b9c14d0ede2f8b25714623bee152800014e1fce4cc990338f32e215f4b4e27206fcc4b3a5e68512290fd3c67fc0ea91db63f4314960ccbd36a3f7d0c2378d3d8c4dbb5269da62863970f96d7ee05e60da9b633adaf32c5575cb18f22acd62b3beb6d4eb38f291a6fe0534feb393baf38ec34ab05817bfcb789d794766a9fb319d35fac5940db3f98df3acc1385dae636b30211e5754df434e39041c9386d9b08c1cd1af3b0d8c026ce4a4e908153d3f93b8c")
	require.NoError(err)
	copy(expected[:], rawExpected1)
	require.Equal(expected, actual)

	s.XORKeyStream(actual[:], actual[:])
	rawExpected2, err := hex.DecodeString("a979ccf0471045f217039bb8346465bda4064bcf38851aaf998e7158101e79d717892a4b1db7dcd1c5f62fd134a25a4bed3e302c424a9ae621fc7a96e2aec93bcbfd65dde16b0a52472922a5c28aa924cc336eb097064cdd80decd7c418b469d37985caed7bdfd88e0db5ed62114d513fe83d2dd1b0a39fe7e76b4d33362bd9b5263fbac8f2c49a59de218b8498a8c5a258a2b7ec23c57435caee2337c482cd71d1340db264ae31b0b2cc83ed2d63a8e7abeaf961783d5b0643d79edc8f5b41348bf568ae62b444a648f70936d92f7eb7427627da1aeb49e662c047ba5d3f3c0c609edf762e39d92fd596468d5fa5f3e9ccc664cb04d4ab0dcbd283448201dfd63e6c1faf6cb834eb2066fa8cae5180d9f530015cebe3226f851dae586208eea312381b89ab19e68c2a3d0357f174378dbd2e43881ab119dda17bda19cd09e923e357ea93f6357d4dac3eb85f8645ca9795be968955fb60c9b8f05e031fadbdfaf257517a12049574b34678a85d97be128bd4cc9b06102a2c2a5a0cc277cbca184f1213856448a0dc9a520f0a50fcb87c08ff0b86538c7ea4da753b35c89cf9cfa5ca00254fabc69f40b6c266a2ba77011c8ee4d68ab9c3c379128ace428eb730bf13ddafb0a0fee30918922229822c0eb99646846a3ea5e980a8d309602b4c729c6ab66813c3912dc129cf622d6b2ac1b9f9eeca70d56c81d8f1615170f8e5657556f814fd1c165ee412252d2f74aa9a40c7309c9b2510136546225533803b90d7c1f83855bf67c67269ecc6441d69423ca002fb194b73c638aa552ecb421831abee5cc5000a348fea5b463fed41a786742a2af937c7b0bc85d252e0fd5d0dd5ba2c3061446f07d89c8fb4fb3b3450caac9e291cd7e0cfac8bc053e3332dc193f7ca615ee56ebb6ca33040a43c5a7d5741d1b5e3ecfc4141653dd34ffe2c4d357b4147ae62e15a4d401e1acbeb3a4e68588873ce717f274a08487d2fc75f91d8911824a5f35771e798d52e7db56c8d2de1e23ead41e4699d00116b6e5bbcf2172f5ad471498d5efdb49ee833dc2c53dabfbd75b82f669d0b722e8467a0345ac0c0cd9070afa9449213b6d955e643c041d8700f6669efdca5fcf050b909b10fd32b3dd66109b171f283ea244a5b3d5fab54820aa707968bc2a450a4bde1b4f17ca5a4e984410bd8baa5d873e726891658121b749dee1e500ddde8af1b88bf35b13daf3e31c53e90f07e7d99fe3608224648d78b56549f9a0fe8047c72292750a6c66cfade63768563dc1eed4a084e447fa5b201e9e8601f02b118b5ad066a1c0bc9434d0e923fc935568c215d26efe4969618998f82f71176d533e9df1fd497d9aacd378e7b4674ea6f7a110be41cf8fab7c1882d4137ae67e096bf793b7cb764de3c7654ee1a745778c3ff11102a60a877d4701fc0943eb48af55ac4f8ba567")
	require.NoError(err)
	copy(expected[:], rawExpected2)
	require.Equal(expected, actual)

	s.Reset()
}

func TestSPRP(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var key [SPRPKeyLength]byte
	_, err := rand.Read(key[:])
	require.NoError(err, "failed to read SPRP key")

	var iv [SPRPIVLength]byte
	_, err = rand.Read(iv[:])
	require.NoError(err, "failed to read SPRP IV")

	var src [1024]byte
	_, err = rand.Read(src[:])
	require.NoError(err, "failed to read source buffer")

	dst := SPRPEncrypt(&key, &iv, src[:])
	assert.NotEqual(src[:], dst, "SPRPEncrypt() did not encrypt")

	dst = SPRPDecrypt(&key, &iv, dst[:])
	assert.Equal(src[:], dst, "SPRPDecrypt() did not decrypt")
}

func TestKDF(t *testing.T) {
	assert := assert.New(t)

	ikm := make([]byte, GroupElementLength)
	okm := hkdfExpand(sha256.New, ikm, []byte(kdfInfo), okmLength)

	k := KDF(ikm)
	require.Equal(t, okm[:MACKeyLength], k.HeaderMAC[:])
	okm = okm[MACKeyLength:]
	assert.Equal(okm[:StreamKeyLength], k.HeaderEncryption[:])
	okm = okm[StreamKeyLength:]
	assert.Equal(okm[:StreamIVLength], k.HeaderEncryptionIV[:])
	okm = okm[StreamIVLength:]
	assert.Equal(okm[:SPRPKeyLength], k.PayloadEncryption[:])
	okm = okm[SPRPKeyLength:]
	assert.Equal(okm, k.BlindingFactor[:])

	k.Reset()
	assert.Zero(k.HeaderMAC)
	assert.Zero(k.HeaderEncryption)
	assert.Zero(k.HeaderEncryptionIV)
	assert.Zero(k.PayloadEncryption)
	zeros := make([]byte, ctidh.PrivateKeySize)
	require.Equal(t, zeros, k.BlindingFactor)
}

func TestVectorKDF(t *testing.T) {
	assert := assert.New(t)

	ikm := make([]byte, GroupElementLength)

	rawInput, err := hex.DecodeString("684d39265ab9a2d1dfe00aa455360ad5ed6ff6e6034525d0dd9cdbc38884b47b5b5ae1521b7ffebd1d9141bfe836bcdcbc9fd3285a845566bb23c7e4c0a7e391e9477e322402019247b713a3c15178a421a47ad21b02f767f866d84d2e4f9d9fee7177d04c765639da2ceee7621c3ce87c00ca4af36ab95cc11f4fd0ba8892d8283ec2e30115e680966f3ab1ace74d8df3ce2ae7795e6d52b54ea2c2a8b8607a14ef311f9fda10967dc1daef9784db2af9d9fc0f6b76f422acd9afc055778bc814c5bfbb549be72a3f20ce7bc1269f40384496ba272be34cf0263fb560a83f91a20fe5e6f0442c5f39a3d6fc3a2a28c0e61326e263e061c79a38e6457242d999")
	assert.NoError(err)
	copy(ikm, rawInput)
	k := KDF(ikm)

	rawHeaderMAC, err := hex.DecodeString("6d02c4e427c441dc99aa7ba3b669c3aee049bc785a06de1f4f3d67b78557a6b2")
	assert.NoError(err)
	assert.Equal(rawHeaderMAC, k.HeaderMAC[:])

	rawHeaderEncryption, err := hex.DecodeString("a54c045d73bd14d6451aa0fbbf44bce7")
	assert.NoError(err)
	assert.Equal(rawHeaderEncryption, k.HeaderEncryption[:])

	rawHeaderEncryptionIV, err := hex.DecodeString("eb5b5249ea52249834ddf25a2b49e8bd")
	assert.NoError(err)
	assert.Equal(rawHeaderEncryptionIV, k.HeaderEncryptionIV[:])

	rawPayloadEncryption, err := hex.DecodeString("be91da7fcbd77ecbe3260ca6736f0facf750e1bf55ec6ecb07de89dc5aa63fc2f775b122e0cbe91ac63cd94fb5a39b55")
	assert.NoError(err)
	assert.Equal(rawPayloadEncryption, k.PayloadEncryption[:])

	rawBlindingFactor, err := hex.DecodeString("49b347333c66afbe5707dae0e979c52fd856378232746863fb1c1c71eeff2c8d47314cf049222f2bae75b733c588c7c9e1ce39e45220851b3c2bc43a9b76fd6dfccf49942e7c7c7fa151f25a083f876f82b19723aaa6df770190f03d09081f0aa134d4481ade2cc02bd4fd2df5f8ab4a0cd2302eb2b43360bfb0b2e1fe9241bbe3cff9416cbb7f7367248ced28350a1d70cd3f96d27ddaf1ae97079796dad2bff54fce8bd1076c7ebf8294392a82f0765ceb31368a46bb05e9df86fcfdb99e1805d4402ed8c9f1c2fd36e11e0f652b1da431b241f56431cd3d00fab84aeef33a92be99e58c157e")
	assert.NoError(err)
	assert.Equal(rawBlindingFactor, k.BlindingFactor[:])
}
