package python

import (
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var interpreterColdRanges = map[host.FileID]util.Range{
	// ==== Alpines apk ====
	// alpine:3.20 BuildID 4913fe1380aebd0f4f0d69411b797d7e22d2799b
	host.FileID(0x9c4acf83b333e10): {
		Start: 0x88a9a,
		End:   0x88a9a + 0xdcdf,
	},
	// alpine:3.21 f0f26a21d40d3c089975a8b136fc2469df40a0e6
	host.FileID(0x22a639a613e509ad): {
		Start: 0x89228,
		End:   0x89228 + 0x35d9,
	},

	// python:3.11.3-alpine3.18
	host.FileID(0xebcedc88a349c860): {
		Start: 0x1034cd,
		End:   0x1034cd + 0x4974,
	},
	// python:3.11.5-alpine3.18
	host.FileID(0x4b1c70c36f0075f9): {
		Start: 0x104470,
		End:   0x104470 + 0x4979,
	},
	// python:3.11.6-alpine3.18
	host.FileID(0x4283821f868562f4): {
		Start: 0x104613,
		End:   0x104613 + 0x495f,
	},
	// python:3.11.7-alpine3.18
	host.FileID(0x15d73b3f944848d3): {
		Start: 0x10469d,
		End:   0x10469d + 0x4977,
	},
	// python:3.11.8-alpine3.18
	host.FileID(0xf29fa873a032184c): {
		Start: 0x1046fc,
		End:   0x1046fc + 0x49bf,
	},
	// python:3.11.9-alpine3.18
	host.FileID(0xb4a78ae6f0d16188): {
		Start: 0x104865,
		End:   0x104865 + 0x49a9,
	},
	// python:3.12.0-alpine3.18
	host.FileID(0x459fa7472e2f0fc6): {
		Start: 0x11590f,
		End:   0x11590f + 0xe6db,
	},
	// python:3.12.1-alpine3.18
	host.FileID(0x69608dbd79fe8d8e): {
		Start: 0x115cb7,
		End:   0x115cb7 + 0xe710,
	},
	// python:3.12.1-alpine3.19 BuildId a4970cc76c9399f016ebd17fc6d8b025a28a8fb9
	host.FileID(0x92058c121173e39): {
		Start: 0x113712,
		End:   0x113712 + 0xeb19,
	},
	// python:3.12.2-alpine3.18
	host.FileID(0xb4fc08fe0a06e06c): {
		Start: 0x115c27,
		End:   0x115c27 + 0xe6cb,
	},
	// python:3.12.2-alpine3.19 BuildId 491c833bb4e1551c24f469bbed864bc6cf6f3966
	host.FileID(0x723515b605bbe10d): {
		Start: 0x113770,
		End:   0x113770 + 0xeb6c,
	},
	// python:3.12.3-alpine3.18
	host.FileID(0xfe2eb6244c8724fa): {
		Start: 0x115f03,
		End:   0x115f03 + 0xe77f,
	},
	// python:3.12.3-alpine3.19 BuildId 57f7bf9f701577aaaba8a90683318b763ff55692
	host.FileID(0xf6296b664549496e): {
		Start: 0x113b13,
		End:   0x113b13 + 0xebba,
	},
	// python:3.12.3-alpine3.20 BuildId 225f76e29d3a1aad3d04a12db446d82b7f40769f
	host.FileID(0x90ee0b0defe866ee): {
		Start: 0x113ab7,
		End:   0x113ab7 + 0xebc9,
	},
	// python:3.12.4-alpine3.19 BuildId b00993bf9f47921daa7913742279b3f61c1cc394
	host.FileID(0xc0b598f9998896cc): {
		Start: 0x114afd,
		End:   0x114afd + 0xeaeb,
	},
	// python:3.12.4-alpine3.20 BuildId 5aca1b7999d21d23fdec074c8d5667fd49f0510e
	host.FileID(0x7e734e63beab2279): {
		Start: 0x114a96,
		End:   0x114a96 + 0xeb1d,
	},
	// python:3.12.5-alpine3.19 BuildId 458475b6acc26f4186e078a91594edceb2f23fae
	host.FileID(0x5f3d3a98ae7d00ca): {
		Start: 0x114b86,
		End:   0x114b86 + 0xea0b,
	},
	// python:3.12.5-alpine3.20 BuildId 033bb7b8ec0edba2c77c54792c2a6f1be8e28afc
	host.FileID(0x957c54bd358cc902): {
		Start: 0x114b0a,
		End:   0x114b0a + 0xea15,
	},
	// python:3.12.6-alpine3.19 BuildId 70dd7d13bf106f898d76bf6ae9903b0b0ef8b09a
	host.FileID(0x6ff1f2938a5ad7b2): {
		Start: 0x114b39,
		End:   0x114b39 + 0xeb3b,
	},
	// python:3.12.6-alpine3.20 BuildId 4eae81b751b9b32782743b25a7377485ba117c81
	host.FileID(0x62632b30fae656d7): {
		Start: 0x114bc2,
		End:   0x114bc2 + 0xeb02,
	},
	// python:3.12.7-alpine3.19 BuildId 583ef43f17375e10e6ccf6e32715fd334caa636f
	host.FileID(0x2d9eb887120bb467): {
		Start: 0x107a42,
		End:   0x107a42 + 0xe,
	},
	// python:3.12.7-alpine3.20 BuildId c16c6dd826d1eddfdef8595c4ff89fcf7897f8a2
	host.FileID(0xb541cd58b8f3a5bc): {
		Start: 0x107a42,
		End:   0x107a42 + 0xe,
	},
	// python:3.12.8-alpine3.19 BuildId abf8f3958ceb2a35e7f0e4477b4c206f63de0b7f
	host.FileID(0x4b621e87bb72b0be): {
		Start: 0x108a52,
		End:   0x108a52 + 0xe,
	},
	// python:3.12.8-alpine3.20 BuildId 3c708e342ae64df09ffee76e911f38a021239de1
	host.FileID(0x751d2d3184407d31): {
		Start: 0x108a56,
		End:   0x108a56 + 0x1a,
	},
	// python:3.12.8-alpine3.21 BuildId 3881591a3c7276cb4b7ab4d1f29f8b2616fd5402
	host.FileID(0x25f0d55f5780f92e): {
		Start: 0x108a87,
		End:   0x108a87 + 0x9,
	},
	// python:3.12.9-alpine3.20 BuildId 3199d7638f0131ba5fb58b8ada7638484bf7de2e
	host.FileID(0xf8bbfd8d5be4ed55): {
		Start: 0x108a66,
		End:   0x108a66 + 0x1a,
	},
	// python:3.12.9-alpine3.21 BuildId da93ad9b44056f688eb174c09a4872c33e362efe
	host.FileID(0x860143f07736c333): {
		Start: 0x108a87,
		End:   0x108a87 + 0x9,
	},
	// python:3.13.0-alpine3.19 BuildId 6114156ed90adf9b08cd37b16fed8b075e9776cf
	// host.FileID(0x978fd3166207cf1e): nope
	// python:3.13.0-alpine3.20 BuildId 9b4f5cd88636f97dca937fced3b600485ecadc84
	// host.FileID(0x973db92fe5e82081): nope
	// python:3.13.1-alpine3.19 BuildId 65be9a86dff01cd21ce887ebe97fcd0788cfe9f0
	// host.FileID(0xf81756cedd4480a7): nope
	// python:3.13.1-alpine3.20 BuildId 754a68c82ddb2f01fa4e2fe0ee64744484df3d7f
	// host.FileID(0x3cb9d67aa7a30350): nope
	// python:3.13.1-alpine3.21 BuildId e542b32c84e680f26712e15f570c757d89aefca1
	// host.FileID(0x735fac961688abea): nope
	// python:3.13.2-alpine3.20 BuildId c7412e86a1a6403c2b34a8df15fe49b10439ea2b
	// host.FileID(0x17dce4f828e3f774): nope
	// python:3.13.2-alpine3.21 BuildId 568a6018a61b4e205f3064b50ea1a77f80f6faa4
	// host.FileID(0x8ae2d34de684893c): nope

	// TODO debian and ubuntu images are also affected
	// this seems impossible to keep
}
