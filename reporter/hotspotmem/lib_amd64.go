package hotspotmem

import (
	_ "embed"
)

//go:embed hotspot_profiler_linux_amd64.so
var embeddedLibLinux []byte
