package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:lll
func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		cgroupv2Path        string
		expectedContainerID string
	}{
		{
			cgroupv2Path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf6f2d169_f2ae_4afa-95ed_06ff2ed6b288.slice/cri-containerd-b4d6d161c62525d726fa394b27df30e14f8ea5646313ada576b390de70cfc8cc.scope",
			expectedContainerID: "b4d6d161c62525d726fa394b27df30e14f8ea5646313ada576b390de70cfc8cc",
		},
		{
			cgroupv2Path:        "/kubepods/besteffort/pod05e102bf-8744-4942-a241-9b6f07983a53/f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
			expectedContainerID: "f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
		},
		{
			cgroupv2Path:        "/kubepods/besteffort/pod897277d4-5e6f-4999-a976-b8340e8d075e/crio-a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
			expectedContainerID: "a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
		},
		{
			cgroupv2Path:        "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod4c9f1974_5c46_44c2_b42f_3bbf0e98eef9.slice/cri-containerd-bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba.scope",
			expectedContainerID: "bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.expectedContainerID, func(t *testing.T) {
			gotContainerID := extractContainerID(tc.cgroupv2Path)
			assert.Equal(t, tc.expectedContainerID, gotContainerID)
		})
	}
}
