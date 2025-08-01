// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:lll
func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		line                string
		expectedContainerID string
	}{
		{
			line:                "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf6f2d169_f2ae_4afa-95ed_06ff2ed6b288.slice/cri-containerd-b4d6d161c62525d726fa394b27df30e14f8ea5646313ada576b390de70cfc8cc.scope",
			expectedContainerID: "b4d6d161c62525d726fa394b27df30e14f8ea5646313ada576b390de70cfc8cc",
		},
		{
			line:                "0::/kubepods/besteffort/pod05e102bf-8744-4942-a241-9b6f07983a53/f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
			expectedContainerID: "f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
		},
		{
			line:                "0::/kubepods/besteffort/pod897277d4-5e6f-4999-a976-b8340e8d075e/crio-a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
			expectedContainerID: "a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
		},
		{
			line:                "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod4c9f1974_5c46_44c2_b42f_3bbf0e98eef9.slice/cri-containerd-bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba.scope",
			expectedContainerID: "bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba",
		},
		{
			line: "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-868f9513-eee8-457d-8e36-1b37ae8ae622.scope",
		},
		{
			line: "0::/../../user.slice/user-501.slice/session-3.scope",
		},
		{
			line:                "0::/system.slice/docker-b1eba9dfaeba29d8b80532a574a03ea3cac29384327f339c26da13649e2120df.scope/init",
			expectedContainerID: "b1eba9dfaeba29d8b80532a574a03ea3cac29384327f339c26da13649e2120df",
		},
	}

	for _, tc := range tests {
		t.Run(tc.expectedContainerID, func(t *testing.T) {
			reader := strings.NewReader(tc.line)
			gotContainerID := parseContainerID(reader)
			assert.Equal(t, tc.expectedContainerID, gotContainerID)
		})
	}
}
