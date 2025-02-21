package libpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegex(t *testing.T) {
	testdata := []struct {
		cgroup, expected string
	}{
		{
			//nolint:lll
			"0::/system.slice/docker-8e126766ee34e1d3b203c0a7cfc2a619c49d482a2ecc99a190fff577111a4dca.scope",
			//nolint:lll
			"/system.slice/docker-8e126766ee34e1d3b203c0a7cfc2a619c49d482a2ecc99a190fff577111a4dca.scope",
		},
		{
			//nolint:lll
			"12:blkio:/kubepods/burstable/pod7e5f5ac0-1af4-49ab-8938-664970a26cfd/9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f",
			//nolint:lll
			"/kubepods/burstable/pod7e5f5ac0-1af4-49ab-8938-664970a26cfd/9a7c72f122922fe3445ba85ce72c507c8976c0f3d919403fda7c22dfe516f66f",
		},
		{
			//nolint:lll
			"12:blkio:/kubepods/burstable/pod83ca8044-3e7c-457b-8647-a21dabad5079/57ac76ffc93d7e7735ca186bc67115656967fc8aecbe1f65526c4c48b033e6a5",
			//nolint:lll
			"/kubepods/burstable/pod83ca8044-3e7c-457b-8647-a21dabad5079/57ac76ffc93d7e7735ca186bc67115656967fc8aecbe1f65526c4c48b033e6a5",
		},
	}
	for _, td := range testdata {
		pathParts := cgroupv2PathPattern.FindStringSubmatch(td.cgroup)
		require.Equal(t, td.expected, pathParts[1])
	}
}
