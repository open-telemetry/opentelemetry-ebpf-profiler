// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDebugIDRegex(t *testing.T) {
	shouldMatch := map[string]string{
		"// Built with esbuild - minified for production\nimport*as m from'http';var c=process.env.PORT||3e3,l,f=!0;process.exit(1)}}$();\n//# sourceMappingURL=server.js.map\n//# debugId=25f5c240-2294-5287-af80-41686c416a20\n": "25f5c240-2294-5287-af80-41686c416a20",
		"//# debugId=25f5c240-2294-5287-af80-41686c416a20": "25f5c240-2294-5287-af80-41686c416a20",
	}
	for s, expected := range shouldMatch {
		matches := debugIDRegex.FindStringSubmatch(s)
		if !assert.Len(t, matches, 2, "regex %s should match %s with one submatch", debugIDRegex.String(), s) {
			continue
		}
		assert.Equal(t, expected, matches[1], "regex %s should extract debug ID %s from %s", debugIDRegex.String(), expected, s)
	}

	shouldNotMatch := []string{
		"// Regular JS file without debug ID\nconst x = 1;\n",
		"//# sourceMappingURL=server.js.map\n",
		"// debugId without the #\n//debugId=25f5c240-2294-5287-af80-41686c416a20",
		"// Invalid UUID format\n//# debugId=not-a-valid-uuid",
		"",
	}
	for _, s := range shouldNotMatch {
		matches := debugIDRegex.FindStringSubmatch(s)
		assert.Nil(t, matches, "regex %s should not match %s", debugIDRegex.String(), s)
	}
}
