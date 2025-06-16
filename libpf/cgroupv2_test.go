package libpf

import (
	"os"
	"testing"
)

func TestExtractContainerID(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
	}{
		"perf": {
			input:    "10:perf_event:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf6f2d169_f2ae_4afa-95ed_06ff2ed6b288.slice/cri-containerd-b4d6d161c62525d726fa394b27df30e14f8ea5646313ada576b390de70cfc8cc.scope",
			expected: "b4d6d161c62525d726fa394b27df30e14f8ea5646313ada576b390de70cfc8cc",
		},
		"besteffort": {
			input:    "2:foobar:/kubepods/besteffort/pod05e102bf-8744-4942-a241-9b6f07983a53/f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
			expected: "f52a212505a606972cf8614c3cb856539e71b77ecae33436c5ac442232fbacf8",
		},
		"crio": {
			input:    "3:crio:/kubepods/besteffort/pod897277d4-5e6f-4999-a976-b8340e8d075e/crio-a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
			expected: "a4d6b686848a610472a2eed3ae20d4d64b6b4819feb9fdfc7fd7854deaf59ef3",
		},
		"scope": {
			input:    "4:scope:/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod4c9f1974_5c46_44c2_b42f_3bbf0e98eef9.slice/cri-containerd-bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba.scope",
			expected: "bacb920470900725e0aa7d914fee5eb0854315448b024b6b8420ad8429c607ba",
		},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", name)
			if err != nil {
				t.Fatal(err)
			}
			defer tmpFile.Close()

			if _, err := tmpFile.Write([]byte(tc.input)); err != nil {
				t.Fatal(err)
			}

			if _, err := tmpFile.Seek(0, 0); err != nil {
				t.Fatal(err)
			}

			result, err := extractContainerID(tmpFile)
			if err != nil {
				t.Fatal(err)
			}
			//t.Log(result)
			if result != tc.expected {
				t.Fatalf("expected '%s' but got '%s'", tc.expected, result)
			}

		})
	}
}
