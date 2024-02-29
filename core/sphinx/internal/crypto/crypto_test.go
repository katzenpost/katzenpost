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

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	ourVeryOwnRand "github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestHash(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	assert := assert.New(t)
	mesg, err := hex.DecodeString("f72fbd7f19e0f192524aea4973354479d6507d964242b30ded31c87e81c5c889")
	assert.NoError(err)
	hash := Hash(mesg)
	want, err := hex.DecodeString("9b931e466dc077f2cdf57784996dd19006a60e411692a8bdca4882c129c03a86")
	assert.NoError(err)
	assert.Equal(hash[:], want)
}

func TestMAC(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
}

func TestStream(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	require := require.New(t)

	var key [StreamKeyLength]byte
	rawKey, err := hex.DecodeString("a64928fd9d379ef8089a3a8fc32423c473b0e615b31d380394f10afc7f195df9")
	require.NoError(err, "failed to read Stream key")
	copy(key[:], rawKey)

	var iv [StreamIVLength]byte
	rawIv, err := hex.DecodeString("ff03c942f5c95a5eca94b1047a6e327e")
	require.NoError(err, "failed to read Stream IV")
	copy(iv[:], rawIv)

	s := NewStream(&key, &iv)
	var expected, actual [1024]byte
	s.KeyStream(actual[:])
	rawExpected1, err := hex.DecodeString("754af881d3a711ccaba1b2464ca70ef1389e6b607a6cdc573ab4d999a1f70c9f3f02f23c83b5a9fd7e2106a0ddafc5cfc822c2a59d64fc4ee0b91995afbf17577db3a771a2a5f91fcb7a4f868d0f73ab5a131104a23e2b9f5d3a003f20de653ea26e411b7e8079298b6fab857b80ad22e6a9907ffc3577e08148362ecd07edc7fbe7e177c086cf2b89d0f695dce1c0630a021560ba421cd8e86fe0e13057dba0de39a81d45bf4ee2fb53086b6868b7af8963597f39a8c00c3cac94650186044407539b957710d23373a7ddcfe896d3d430e6aa454c80f0aea9e2984625774367ae5b51b85e7fd4581db371037395e41be1dce6ff7b003e7c070cecce9e207ae3aead3d0b7f822714bdbc550f4dbf9c3159716bbb0d92b9b637da5498233904cd13ee58a30f9b615d2591e16cfc56aa2386f85c99884092253689c4fa227f7e03d518cf422286af9368a8e88ffe43283dfee7c36516f812ffcd2799e2b8d46b8b9695f573d3bf211e4e1525bc20fbf7dc3534f0ebc28abe09727f31d6c349ce1a5d2fb34413bddc2dd2f1a3769961009d94a5c4c5c03aeb2aa87ae4c433069153e0026fa46e4e8a8fce583ff882f4f0304e3f056de8368199a96b2675994b834c89e7d1f9b192b8ce9fae38093cbbd5551b47e792729c67eb5b0a063c29a79538821f9bc712d329edfed70ce6710afa709f3acf5c98247528ba314fec797052e324fce5e0f9b9308bd911d2093d76599d6aecd582d92b08d6105bd241d0e696f6e9fcf24674f37abb642059af160e9fe8879b4256c6b358d1a30bd5b4fb1d0ae3d3ef778327b97276b70f335e239c3ec491d3806ca7eb9e49ccd3624b18835a362fef47c8d4826a58d8c025843670d29940248e88afd42cdb7dd75aa57ae1f610485d6d2e5182fed5d00f641b2850a4f37b772dbed08a239f2801b580ccf616f3ca4368972a4e417066e7574194a7b8df0024a2e00aa9802f57d87a800bb083e68ee88d9175f843cd3716196841000b1ee378273bc1508cf616be071f1801ef7c22c8fd388fccb58463b0f75621e8a1a6e56b7b0c112b80e2c1bd719067086978d772cebd032c5f17672fd192d1ec2882e242364c5329da16c1a980f68c740dffe1f03da59abbee783cbac7753a9208faf1cb90d5a2353cd43188fc60cd0e3a0f5b4ed1406759111a69563438e7b87f55bcbba28e368329dca90a61c82b234065b958b9a9828a0480642a49f37f5ea21879003b53c0b2045b0764a9efc3ae2d750731204137d10a8970bb7a35365b9638e9b2897b9115b02665b86408fcea3ff03d1c1e23b1cf42a5368c45859f4fdaa037b6c2d3f709c6eb8d322f5aa408f99214fa7bbc77a78a69a71945a5c92ff68ec4a1713c688556c0e022cecc277576bacd3fabee83c2e2f3e049536661f99f7707a08236904b9570af44c914c84a2650")
	require.NoError(err)
	copy(expected[:], rawExpected1)
	require.Equal(expected, actual)

	s.XORKeyStream(actual[:], actual[:])
	rawExpected2, err := hex.DecodeString("f1c6c56f5bf86134d9f0d71e7cca108a9d7f7a2dc47a8405221b7c2dcc77e7469b856d91423bfcf1724cb214ca826593af55326f563476c85fdd1f5efbb2b0de8f50d30bce118ee7cbf290ffa2f23c69bcf1afc294c2999333dda5a801c3021d6a2e8b51543d1249064333d4886b0d51e1c1401454a0ad03db850277a49b672755023d6720919aae6bf73aedffb3f1be315f55e991ec0b0df8df0f418afd884e1d32f9386195deb4d26e1a8618656a131ee03423c98cb9c194112a76e1af46d19ab0e20f81a1d458c5e635c584c4e73626008e54ddf1b3ca2ea5217f7594a9fe7b2302395e16b5b20fdab48faed7e33e1c79b969e3133f85a16c4c5c95579ff8ad7e1e0557731248f4f88e4715bd34b81ed0a5ae2616d0463c86f31698ee9d2de41841c6b4ef226b9bc91764a80f5cc04a60c0f010485f71031eea54298e2e4c4769b6e217707579acd237a65dbb3550c4d53b5c4466547ba93fabbabd0e2729e31e710f6c6a980461c0a739549ddfdfad4f89d0bf75ad6c3b6f0ec905b12be29d657d4420289ea7abb5eac1d77e41900a3eec610054c81144385c00081cad53fe657fd9bb47aed04fdbf16c5b252e386ec207052429f98759518183abafad37506ec27538f14ce9ed0a39c1e39fe0e4f4af995f2534a3fb5535cc948147580ba754b14adf6f32f11f55590a0c2677e7b9faaccc7cc9393321dd6c66db32e66e6e6e41f907f4baa97f9f5cba579f9851220cd5380b59869db71dce825725c276c91376dca90ef5be38dc7785f7ed4295ef9be3136ea7663931df66d63a78be8c2151a314f69435bc8f4811d270df80ee8ed9457379ecf9f5ae5917519968f6878d5a77f7cd2f4b02849e0c2c1fe78658f8398eff1567089bf298a7b0563ce04b2c82a080f2748315de2f44e691f71a82c651d8c5756e2176b56bdc6689c8cb0cfb3f89799c4d5ea7aac435b0a113e7716813a057fb4c93172ce63ff31976d4804412eb9501913b6c15903dceafe44018850b552329414fc426487b83b661812ec20be1bba4c73aeffdb76d07547440cec3df1fc85ae7983e90b906cdfd808f5d91af9baf82d8877aac8bb4ae1e0c1cee699645b667a4981292eeb01e68ba490f159defcba4c5a35ce8c4e814cf234819bb37a5808945bcedd52420a6952de0cba9036817f0318efe23af041167e4c067e91be6d53b4452914c93c3e5aa2e8aa4804497ef37e39f7a578839f9b612e042c9565d7507dd995abf276626d72b2c5a75c10bbcb78837ea8bd71fe12589b15a0b71c22be82203a816941b7916ae7ec3e6c92d8e36b88201713e3491c6a8f5e5554d358755e8c46893d6dc1e5b22a39e01ec03a27ce010f7eebf848492938d2f53bd3ac61bef65214d1309f5064d40d02f5d032e8e15ae643706abadfe023f16c49dfddc99e4df5831bc00f685afa092")
	require.NoError(err)
	copy(expected[:], rawExpected2)
	require.Equal(expected, actual)

	s.Reset()
}

func TestSPRP(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	assert := assert.New(t)

	ikm := make([]byte, 32)
	privateKeySize := 32
	okmLength := MACKeyLength + StreamKeyLength + StreamIVLength + SPRPKeyLength + privateKeySize
	okm := make([]byte, okmLength)
	h := hkdf.Expand(sha256.New, ikm[:], kdfInfo)
	count, err := h.Read(okm)
	require.NoError(t, err)
	require.Equal(t, count, okmLength)

	k := KDF(ikm, ecdh.Scheme(rand.Reader))
	require.Equal(t, okm[:MACKeyLength], k.HeaderMAC[:])
	okm = okm[MACKeyLength:]
	assert.Equal(okm[:StreamKeyLength], k.HeaderEncryption[:])
	okm = okm[StreamKeyLength:]
	assert.Equal(okm[:StreamIVLength], k.HeaderEncryptionIV[:])
	okm = okm[StreamIVLength:]
	assert.Equal(okm[:SPRPKeyLength], k.PayloadEncryption[:])
	okm = okm[SPRPKeyLength:]

	priv_reader, err := ourVeryOwnRand.NewDeterministicRandReader(okm[:privateKeySeedSize])
	require.NoError(t, err)
	tmpBlindingFactor := ecdh.Scheme(rand.Reader).GeneratePrivateKey(priv_reader)
	assert.Equal(k.BlindingFactor.Bytes(), tmpBlindingFactor.Bytes())
	okm = okm[privateKeySeedSize:]

	assert.Equal(0, len(okm))

	k.Reset()
	assert.Zero(k.HeaderMAC)
	assert.Zero(k.HeaderEncryption)
	assert.Zero(k.HeaderEncryptionIV)
	assert.Zero(k.PayloadEncryption)
}

func TestVectorKDFWithECDHNike(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	ikm := make([]byte, 32)
	rawInput, err := hex.DecodeString("9dd74a26535e05ba0ddb62e06ef9b3b29b089707b4652b9172d91e529c938b51")
	assert.NoError(err)
	copy(ikm[:], rawInput)
	k := KDF(ikm, ecdh.Scheme(rand.Reader))

	rawHeaderMAC, err := hex.DecodeString("56a3cca100da21fa9823df7884132e89e2155dadbf425e62ba43392c81581a69")
	assert.NoError(err)
	assert.Equal(rawHeaderMAC, k.HeaderMAC[:])
	rawHeaderEncryption, err := hex.DecodeString("fa4f8808bad302e8247cf71dbaefe3ae3499437e566a8f8cae363b428db7eff9")
	assert.NoError(err)
	assert.Equal(rawHeaderEncryption, k.HeaderEncryption[:])
	rawHeaderEncryptionIV, err := hex.DecodeString("382d5480e7ebc3c001d04a350f6da768")
	assert.NoError(err)
	assert.Equal(rawHeaderEncryptionIV, k.HeaderEncryptionIV[:])
	rawPayloadEncryption, err := hex.DecodeString("82f26dff7fd14e304bce0aa6d464e6e4a440aad784b18c062700c352e7df6c4422884af95653aef353d3bd3e8b7f9ac2")
	assert.NoError(err)
	assert.Equal(rawPayloadEncryption, k.PayloadEncryption[:])
	rawBlindingFactor, err := hex.DecodeString("8e869512c77c2c0ca7b718d68b4a571824e788d38b223b921460769c34a89501")
	assert.NoError(err)
	assert.Equal(rawBlindingFactor, k.BlindingFactor.Bytes())
}
