package schemes

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHybridKEM(t *testing.T) {
	s := ByName("Kyber768-X25519")

	t.Logf("ciphertext size %d", s.CiphertextSize())
	t.Logf("shared key size %d", s.SharedKeySize())
	t.Logf("private key size %d", s.PrivateKeySize())
	t.Logf("public key size %d", s.PublicKeySize())
	t.Logf("seed size %d", s.SeedSize())
	t.Logf("encapsulation seed size %d", s.EncapsulationSeedSize())

	pubkey1, privkey1, err := s.GenerateKeyPair()
	require.NoError(t, err)
	ct1, ss1, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)
	ss1b, err := s.Decapsulate(privkey1, ct1)
	require.NoError(t, err)
	require.Equal(t, ss1, ss1b)
	t.Logf("our shared key is %x", ss1)

	ct2, ss2, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)
	require.NotEqual(t, ct1, ct2)
	require.NotEqual(t, ss1, ss2)
}

func TestHybridKEMVectors(t *testing.T) {
	s := ByName("Kyber768-X25519")

	/*
		pubkey1, privkey1, err := s.GenerateKeyPair()
		require.NoError(t, err)

		pubkey1bytes, err := pubkey1.MarshalBinary()
		require.NoError(t, err)
		privkey1bytes, err := privkey1.MarshalBinary()
		require.NoError(t, err)

		t.Logf("pubkey1 %x", pubkey1bytes)
		t.Logf("privkey1 %x", privkey1bytes)
	*/

	privkey1bytes, err := hex.DecodeString("2a809da06d8a06ecd8c94877b4dad40726c41b41ce0b82dccefa67125332317755f539cdfa7f911a89f77c81fa717d4a86680e2a132c27cf0dd360ddca11ed0248efc1b2cee6a6201548543177c096438d953a7aca29445c4f117b466bc76238926293222c386cb7cdeca62e1435542668b7c60c59e8931a6407b8b02ae74b7f4369a1897bbb01e5b9022c5062d500e2e78c678285ad995824fc1e1e3cb0f773557b08a0555203af644f74115ddbb976b646ae6c717ca7678f80726bb8077a846637ff6376e511a7ae694db3e6c96ad321d7620f688511f161b4e365245cf77403bc19b734022c7bb8ad7366b8c693e93cb2f88880d12483a74a933032a134fc57b8c64dac1735af829807a561e287a95a71b3e7f87c446aba94d19fec64ac3355c5e7792888e396ff593dbe09a96e5705fc723e70271debf50c5390b3284452781856542400bb8761ccaa267ba2817e2620784b498fc2bb40db679fa987e3f3cd83e74f9f787fda6c05761b4a59d0c8c360b344d52982183667f54f03752ed48a0a31872a4e022ca242c146f8234bc0b0a75763acb1bedd8a04f88b7cf6dc63143c0f83729fe2dc7dcd08ca66d265fbd330fe60cd204a5000b87799649f8067ac190735300a557a9450f541c3855b012e331cdb6a3fffbca01bc82a20a467f63276841a198d12b1f30a0843b6ad6f98605f8878b1e3cbf7ab8318476d83cc7e352478e1ccbc607c4b895638c445004e5cbda2e004cc4356b0eb15e4c8c1a96b7999c72cf9cb7695171818000459514bb883af9a395e9993aec2fc8ff564c4f9c6a62bc5ce786878365a72c7a9c8a2247ec477385023cd5fb5bd3c5bbc9a7195ba60906190a75222036cf21a49ba11a340a760043c09ac92e0958f38b2668e9c94137a4ea44868221341a1faa732e0568a2520428745bec43f2c8a862a48279696829b63814a62416b09c2306985322a2859929afedc2f24fa8a743c6ab73131cb0564c9932ca2e70152190bff9254d8820b13e64e081841072b91dbe03de56441c5f4599954803b9927ae0146bdf9843fb00eec8755699950df276409121bb723366df76762f732f946563a844749475137ca277bb23ffd20c07da75a5e71836ddcb25e2a97ec37c6ba0709b7935c05f0bda16a7f6c085c847459dad443ba595e5a91bfbff9a75eca894bec22fa54001888600e5626d0129191e31e4a010142c681c880107c97589e8c3a51c05bc0da9d54514e98a3c4d987bc18b35989aa3b1d22123e1906f8e2ab13500a14a54a08c02452d8bc4989864ad508bd03651a0cc6d2ac81e1f4cb55e7ba78a8121bca47f77a8467811db2e7b6d320461bb53b76199f179570b1482ee31c30a3d19f14cbc70fd5361ee600f9c4abb66c57bce18aa3f6162bd6014c56b149e91000dbab34b904a8a0276dd7905e643c60704d0910c90c7989809ca86de71ca5ea8a043426cea13806218dc61455ae81b9ed2608f9408ec35a5003f715d7f164ea02aea3e366dc2563e687729046210bc30f0175a38dd7ad7f819c3b5b3fb979ada1d7a2b8555d99f275a2e05aa73841f3e6b62070950b3a82ed6b4b35d915f8e2396555bbac78ae60f4022a6a9a82975ba1f10587578446340ebac7921cd90b40e3897797c983a09d88858e31e4aa95027dd4c354f9f97b0fe64d2e2350eeb289a338950f89c7ad04ac0590457293871d531cdd44ae48c06a02583216059918346e549abed32b45fb090be7810efbd77b2181ac602092aa5c994ec933593752c7b13bf47bcfe052c1234914a79921bc217b2e2b58ed85bfde125680d34b0f06a218b0ac847a86a7b66974962ff36b7b8fe9a107c39de1381924698da9ecc22365bc39fa146620bf1c829cfe84329be146d25a6bc78a350a5ba68842b75806ca58b804803471789a2cc1094d20d4785ec1a4dc47429709487196386540b4d5651851e11f75193aef2911c23229755baa870b1183fcb80f5085534a979ce99c9a34c2b9c15f0b4764e5db4a0e3717ed9b96d7a06f0a2882fdc75bdeb1ac78e05a48a5bf6756ceb2c3893f4a29a86a95ddf7ba8bd65854b8b212d4cd7ab1044312618aaab02078ca5578b3e1935572906c1502471217ccf6ac582c85c0a4875370052bf7c0c75199b1c8b395a0d52c05aa2e470488906697d286c68c03d0f5686e15443aec0734ff04008f79344be8899cf03d7a1677c6827356864bdd0654a4321c5bb58e8870461dd997eea0add424c1718611cf37ce8e9077bd934d5663a819a99658bc28e084a58199cca189936ae09fdc8445c32bb9d84c0075b3cbce1845aa35749da9547c048d15515b28b7b197c1697ec16ffe507da0e112d040740d19c576f896e9491d76c7ce8df721aac1173428b404317da1146943a32959fac041276d36945c493978149523fec58675b6b83596bbabfc54d4d4bac1f309708a4b3e358cbc5b7415145838605b74589ab4d5a1b9c52aa27bb4a289ca04903c9f2799c301c630813ac7193388b58b94eb14a8e2a8aed74935ecaaa975449f718bd500cc6ff190c143c6251b12051b95a2f1ccd3695dc4eb15561587596622e600347195b7ee561d7381439a98a27b1b840399a5aa0c1ad6da3f4597c8813a72fa30a65fb4c6e08b6d44b08fa8babfa57b186570aab52c82ce053b75b1887cd6113016af4c826c92870b70a7aed06522b1db52a9538951dc66e349825477b5113a3797071c6198c1bacb4ddfe0681a442fbb629c00ad2f296978d62c96e4805f0e58ab37914b3949103426bfcab807997b5a241ca689fac85836bfdff09769d09d7b680e34ea2e1a14a220463b42fb50d8d2884df4b25a894957e531a20529c4a23abe7b51355223d2633ec3201fde957836d52f2a474fc00729954086eb9b73eb745d92d6297682930f04a164746935a1831aecc3591a2068514fd64b67c66497d4694b5adc859805aaa1ca8dc2e2492232544e6330d6a804e6954aa2e73b02762b91ea618edcb32b79434cd5c225772853fa807a014270871d6ed4c4672b18709418f0e3948ec671f837626e116a43fb497dd57fc56c5e675a31169c848b0accddc0a78e5a3dbe5a6e7ba528e4784d9c846062b477d88b55ed0a3a76db7b92554f49d68cef3cc09e2c30c68a4f2cf1715d78270a909c72b75a2c897b4f05327bc2a31282a94189277126b43809baf48a343ec9cc7a48cf5d32697759c94b056ff606c94af1b6c7713252f9c3ebb13b53d359ab137ef8fa3795e1ba9ca98dde1528eb97961531a84fd205ce867de389816a31bd02c0b102f9ad33c1f1b5a406b36823fe7d8035503b50ed1a3f0ff4bd529e2bb40daf99189c27f84378d1202a43f09637a2737f6e902108fe6941a343266892dc29ad2a35d3ca8c5d55dfc66b2ec57c0ca4f9247b11a5e9cd8237e2ef7850d84d7cf1a4")
	require.NoError(t, err)
	pubkey1bytes, err := hex.DecodeString("353453b21cafa937a98cc4dc3976c458bf1a89a74220d6b75a897a6a2f7d987cf9f97b0fe64d2e2350eeb289a338950f89c7ad04ac0590457293871d531cdd44ae48c06a02583216059918346e549abed32b45fb090be7810efbd77b2181ac602092aa5c994ec933593752c7b13bf47bcfe052c1234914a79921bc217b2e2b58ed85bfde125680d34b0f06a218b0ac847a86a7b66974962ff36b7b8fe9a107c39de1381924698da9ecc22365bc39fa146620bf1c829cfe84329be146d25a6bc78a350a5ba68842b75806ca58b804803471789a2cc1094d20d4785ec1a4dc47429709487196386540b4d5651851e11f75193aef2911c23229755baa870b1183fcb80f5085534a979ce99c9a34c2b9c15f0b4764e5db4a0e3717ed9b96d7a06f0a2882fdc75bdeb1ac78e05a48a5bf6756ceb2c3893f4a29a86a95ddf7ba8bd65854b8b212d4cd7ab1044312618aaab02078ca5578b3e1935572906c1502471217ccf6ac582c85c0a4875370052bf7c0c75199b1c8b395a0d52c05aa2e470488906697d286c68c03d0f5686e15443aec0734ff04008f79344be8899cf03d7a1677c6827356864bdd0654a4321c5bb58e8870461dd997eea0add424c1718611cf37ce8e9077bd934d5663a819a99658bc28e084a58199cca189936ae09fdc8445c32bb9d84c0075b3cbce1845aa35749da9547c048d15515b28b7b197c1697ec16ffe507da0e112d040740d19c576f896e9491d76c7ce8df721aac1173428b404317da1146943a32959fac041276d36945c493978149523fec58675b6b83596bbabfc54d4d4bac1f309708a4b3e358cbc5b7415145838605b74589ab4d5a1b9c52aa27bb4a289ca04903c9f2799c301c630813ac7193388b58b94eb14a8e2a8aed74935ecaaa975449f718bd500cc6ff190c143c6251b12051b95a2f1ccd3695dc4eb15561587596622e600347195b7ee561d7381439a98a27b1b840399a5aa0c1ad6da3f4597c8813a72fa30a65fb4c6e08b6d44b08fa8babfa57b186570aab52c82ce053b75b1887cd6113016af4c826c92870b70a7aed06522b1db52a9538951dc66e349825477b5113a3797071c6198c1bacb4ddfe0681a442fbb629c00ad2f296978d62c96e4805f0e58ab37914b3949103426bfcab807997b5a241ca689fac85836bfdff09769d09d7b680e34ea2e1a14a220463b42fb50d8d2884df4b25a894957e531a20529c4a23abe7b51355223d2633ec3201fde957836d52f2a474fc00729954086eb9b73eb745d92d6297682930f04a164746935a1831aecc3591a2068514fd64b67c66497d4694b5adc859805aaa1ca8dc2e2492232544e6330d6a804e6954aa2e73b02762b91ea618edcb32b79434cd5c225772853fa807a014270871d6ed4c4672b18709418f0e3948ec671f837626e116a43fb497dd57fc56c5e675a31169c848b0accddc0a78e5a3dbe5a6e7ba528e4784d9c846062b477d88b55ed0a3a76db7b92554f49d68cef3cc09e2c30c68a4f2cf1715d78270a909c72b75a2c897b4f05327bc2a31282a94189277126b43809baf48a343ec9cc7a48cf5d32697759c94b056ff606c94af1b6c7713252f9c3ebb13b53d359ab137ef8fa3795e1ba9ca98dde1528eb97961531a84fd205ce867de389816a31bd02c0b102f9ad33c1f1b5a406b36823fe7d8035503b50ed1a3f0ff4bd529e2bb40daf99")
	require.NoError(t, err)

	pubkey1, err := s.UnmarshalBinaryPublicKey(pubkey1bytes)
	require.NoError(t, err)

	privkey1, err := s.UnmarshalBinaryPrivateKey(privkey1bytes)
	require.NoError(t, err)

	/*
		seed := make([]byte, s.SeedSize())
		_, err = rand.Reader.Read(seed)
		require.NoError(t, err)

		t.Logf("seed %x", seed)
	*/

	seed, err := hex.DecodeString("4d29bfc63cfc83dd037a2641d4b2ed177af8d2ef351f7fa87f343475000fdf77")
	require.NoError(t, err)

	ct1, ss1, err := s.EncapsulateDeterministically(pubkey1, seed)
	require.NoError(t, err)

	ct2, err := hex.DecodeString("5da9e5f65ed2e0d49ee6ea6fb76d82f5e84cbf8c244d6a510fb9f0f96367de440706e4ff50d71e4d4fc960ffc25c8bc954449975262b6daecba4a33ce9a6137aa69877fed12d766d79d2d8c7e5cc6949684df406ce3094ab9f7129b49b038800e8fec5b4d995237ffdb6d01ad93b374a848e03571042e68ea746a1b5088411a4712391b71184daee596293eb672164dd2d7ca3fd0c5213d58c955f5921e60fd732d278b41f7531e538f519bcb8e4a577400df23e78142139c7410ed5dd1dc786e41731dad2f548acbf440ea0d8a078ed2c52fd829338afc458eb2b1a80dc5af2c1d8b8e95209a6eb4b4464c5fb6dde26a8d34e20df4107553a656146735a5089701dfe079a4a18246e94cc9a0612d6bd669e9c8e4ecb72e6ff6686c3b8f346d75db3293df3e4e918fd8520654739c0d2caed8cbbeaed64fe5b03c022ff1333b6249ba7a5ffefc30ab202265fada588b825c9af9b9468281d52593a5dbf1b97c09ce40a9985b5deeb99f87cf7d68c1417235c86f02bddd41023d8b57df55fe89e7f2d52cf8f3d138a9adce071a2767c278c26cd7e13d2affd3f0e87b74e0bbb4a37a1d9c01400b2392be886c9b39995976959d3610fc5429b91723525d51431e89b6e765030f6ee38b887ad2282048d68fffff0d5be2d5b93bdcbe85f690dc0d94c21653692f5a1730de682d3a36e28a8b8696416633c251b76762543e0782cb515011fb9072626853c78b3226bcc6bf6baee1002f2545d956a12d4e7397b7f34392944d95ec37bf9876a540e47d16b116e1e1eadf5ebd2d41d060a7baef8dbd978926ac5a1a6931dcbe63e9ecddb96607a6392a2736a76050cc933d4efb82ac0b1a32e259e84c272f80a27963927039cfcb6e0f7947d853dfc4eff32b6ee317490112784fc6d9575458acee7b5f8a12e88cfbf9e8f357831b5913755fa0c0f7b73069e7a663ceb87469688ce5515a5c62f86cfe94234430bb6d1314f185e5bb15796768aaf8f016df1fee8b6e6d0832aaeb917d41b92fea180da055bf5386d36fc35b7f8927f5dbef315a88abf4bb9fbb3751a8b1211c66e6ca3881ddca4e321448511a3d21f8f76b59a12ef0ba27c871e14552df29b3aeb9bd38b6477532a8e7f8e617c296a2b29f3de933a7895ced7372af236ac23340016ba3928817750b32008580767e681c4f58215c9b4d16cfeb8f5a16b0416001178c668b4a60cf17b5197f74bb41a08dd04cc1148516bbce27dc8c272d36dd2d5516785e734bbef7d5a28a987782e7e754bb7bb804fd4becd6839846431f5f96ee0ca55df1d3a857c032b3c2a76807edf9676953a23ac150d2ac0611099d832e6aeb210e18844d31c57745da894cc6bf6ed1815f797e6f27cd69491f4087edd2aaf7ad738b7f4829c2d745b3b8143187781828c31cf0dc05604b65d13c9fb93b06a5c583becd6f3777017497712b8557aac78b0d7467b156fe13aef9701c13d5e1edd868f5314a225e99235baa46651503445f987b060cf71e21f8ebf391ea9c3bb10f56fa42145b7cccdc424df615f0df833e4c998f4b24487316ada5f2b195dc1b73558ba5033c4")
	require.NoError(t, err)

	ss2, err := hex.DecodeString("4e9387611e3c75570101d72f9a329afad419538ecd596f10c2c7461c9dc5c057")
	require.NoError(t, err)
	require.Equal(t, ct1, ct2)
	require.Equal(t, ss1, ss2)
	ss1b, err := s.Decapsulate(privkey1, ct1)
	require.NoError(t, err)
	require.Equal(t, ss1, ss1b)
}
