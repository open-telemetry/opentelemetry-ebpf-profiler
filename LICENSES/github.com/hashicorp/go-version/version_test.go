// Copyright IBM Corp. 2014, 2025
// SPDX-License-Identifier: MPL-2.0

package version

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestNewVersion(t *testing.T) {
	cases := []struct {
		version string
		err     bool
	}{
		{"", true},
		{"1.2.3", false},
		{"1.0", false},
		{"1", false},
		{"1.2.beta", true},
		{"1.21.beta", true},
		{"foo", true},
		{"1.2-5", false},
		{"1.2-beta.5", false},
		{"\n1.2", true},
		{"1.2.0-x.Y.0+metadata", false},
		{"1.2.0-x.Y.0+metadata-width-hyphen", false},
		{"1.2.3-rc1-with-hyphen", false},
		{"1.2.3.4", false},
		{"1.2.0.4-x.Y.0+metadata", false},
		{"1.2.0.4-x.Y.0+metadata-width-hyphen", false},
		{"1.2.0-X-1.2.0+metadata~dist", false},
		{"1.2.3.4-rc1-with-hyphen", false},
		{"1.2.3.4", false},
		{"v1.2.3", false},
		{"foo1.2.3", true},
		{"1.7rc2", false},
		{"v1.7rc2", false},
		{"1.0-", false},
		{"controller-v0.40.2", true},
		{"azure-cli-v1.4.2", true},
	}

	for _, tc := range cases {
		_, err := NewVersion(tc.version)
		if tc.err && err == nil {
			t.Fatalf("expected error for version: %q", tc.version)
		} else if !tc.err && err != nil {
			t.Fatalf("error for version %q: %s", tc.version, err)
		}
	}
}

func TestNewVersionWithPrefix(t *testing.T) {
	cases := []struct {
		version string
		prefix  string
		err     bool
	}{
		{"", "release-", true},
		{"rel-1.2.3", "release-", true},
		{"release_1.2.3", "release-", true},
		{"release_1.2.0-x.Y.0+metadata", "release_", false},
		{"release-1.2.0-x.Y.0+metadata-width-hyphen", "release-", false},
		{"myrelease-1.2.3-rc1-with-hyphen", "myrelease-", false},
		{"prefix-1.2.3.4", "prefix-", false},
		{"controller-v0.40.2", "controller-", false},
		{"azure-cli-v1.4.2", "azure-cli-", false},
	}

	for _, tc := range cases {
		_, err := NewVersion(tc.version, WithPrefix(tc.prefix))
		if tc.err && err == nil {
			t.Fatalf("expected error for version: %q", tc.version)
		} else if !tc.err && err != nil {
			t.Fatalf("error for version %q: %s", tc.version, err)
		}
	}
}

func TestNewSemver(t *testing.T) {
	cases := []struct {
		version string
		err     bool
	}{
		{"", true},
		{"1.2.3", false},
		{"1.0", false},
		{"1", false},
		{"1.2.beta", true},
		{"1.21.beta", true},
		{"foo", true},
		{"1.2-5", false},
		{"1.2-beta.5", false},
		{"\n1.2", true},
		{"1.2.0-x.Y.0+metadata", false},
		{"1.2.0-x.Y.0+metadata-width-hyphen", false},
		{"1.2.3-rc1-with-hyphen", false},
		{"1.2.3.4", false},
		{"1.2.0.4-x.Y.0+metadata", false},
		{"1.2.0.4-x.Y.0+metadata-width-hyphen", false},
		{"1.2.0-X-1.2.0+metadata~dist", false},
		{"1.2.3.4-rc1-with-hyphen", false},
		{"1.2.3.4", false},
		{"v1.2.3", false},
		{"foo1.2.3", true},
		{"1.7rc2", true},
		{"v1.7rc2", true},
		{"1.0-", true},
		{"controller-v0.40.2", true},
		{"azure-cli-v1.4.2", true},
	}

	for _, tc := range cases {
		_, err := NewSemver(tc.version)
		if tc.err && err == nil {
			t.Fatalf("expected error for version: %q", tc.version)
		} else if !tc.err && err != nil {
			t.Fatalf("error for version %q: %s", tc.version, err)
		}
	}
}

func TestCore(t *testing.T) {
	cases := []struct {
		v1 string
		v2 string
	}{
		{"1.2.3", "1.2.3"},
		{"2.3.4-alpha1", "2.3.4"},
		{"3.4.5alpha1", "3.4.5"},
		{"1.2.3-2", "1.2.3"},
		{"4.5.6-beta1+meta", "4.5.6"},
		{"5.6.7.1.2.3", "5.6.7"},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("error for version %q: %s", tc.v1, err)
		}
		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("error for version %q: %s", tc.v2, err)
		}

		actual := v1.Core()
		expected := v2

		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("expected: %s\nactual: %s", expected, actual)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.2.3", "1.4.5", -1},
		{"1.2-beta", "1.2-beta", 0},
		{"1.2", "1.1.4", 1},
		{"1.2", "1.2-beta", 1},
		{"1.2+foo", "1.2+beta", 0},
		{"v1.2", "v1.2-beta", 1},
		{"v1.2+foo", "v1.2+beta", 0},
		{"v1.2.3.4", "v1.2.3.4", 0},
		{"v1.2.0.0", "v1.2", 0},
		{"v1.2.0.0.1", "v1.2", 1},
		{"v1.2", "v1.2.0.0", 0},
		{"v1.2", "v1.2.0.0.1", -1},
		{"v1.2.0.0", "v1.2.0.0.1", -1},
		{"v1.2.3.0", "v1.2.3.4", -1},
		{"1.7rc2", "1.7rc1", 1},
		{"1.7rc2", "1.7", -1},
		{"1.2.0", "1.2.0-X-1.2.0+metadata~dist", 1},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.Compare(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s <=> %s\nexpected: %d\nactual: %d",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func TestVersionCompareWithPrefix(t *testing.T) {
	cases := []struct {
		v1       string
		v1Prefix string
		v2       string
		v2Prefix string
		expected int
	}{
		{"controller-v0.40.2", "controller-", "controller-v0.40.3", "controller-", -1},
		{"0.40.4", "", "controller-v0.40.2", "controller-", 1},
		{"0.40.4", "", "controller-v0.40.4", "controller-", 0},
		{"azure-cli-v1.4.2", "azure-cli-", "azure-cli-v1.4.2", "azure-cli-", 0},
		{"azure-cli-v1.4.1", "azure-cli-", "azure-cli-v1.4.2", "azure-cli-", -1},
		{"1.4.3", "", "azure-cli-v1.4.2", "azure-cli-", 1},
		{"v1.4.3", "", "azure-cli-v1.4.2", "azure-cli-", 1},
		{"controller-v1.4.1", "controller-", "azure-cli-v1.4.2", "azure-cli-", -1},
	}

	for _, tc := range cases {
		var v1 *Version
		var err error
		if tc.v1Prefix != "" {
			v1, err = NewVersion(tc.v1, WithPrefix(tc.v1Prefix))
		} else {
			v1, err = NewVersion(tc.v1)
		}
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		var v2 *Version
		if tc.v2Prefix != "" {
			v2, err = NewVersion(tc.v2, WithPrefix(tc.v2Prefix))
		} else {
			v2, err = NewVersion(tc.v2)
		}
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.Compare(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s <=> %s\nexpected: %d\nactual: %d",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func TestVersionAccessorsWithPrefix(t *testing.T) {
	v, err := NewVersion("controller-v1.2.0-beta.2+build.5", WithPrefix("controller-"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if got := v.Prefix(); got != "controller-" {
		t.Fatalf("expected prefix %q, got %q", "controller-", got)
	}

	if got := v.Original(); got != "controller-v1.2.0-beta.2+build.5" {
		t.Fatalf("expected original %q, got %q", "controller-v1.2.0-beta.2+build.5", got)
	}

	if got := v.String(); got != "1.2.0-beta.2+build.5" {
		t.Fatalf("expected string %q, got %q", "1.2.0-beta.2+build.5", got)
	}

	if got := v.Metadata(); got != "build.5" {
		t.Fatalf("expected metadata %q, got %q", "build.5", got)
	}

	if got := v.Prerelease(); got != "beta.2" {
		t.Fatalf("expected prerelease %q, got %q", "beta.2", got)
	}

	expectedSegments := []int{1, 2, 0}
	if got := v.Segments(); !reflect.DeepEqual(got, expectedSegments) {
		t.Fatalf("expected segments %#v, got %#v", expectedSegments, got)
	}

	expectedSegments64 := []int64{1, 2, 0}
	if got := v.Segments64(); !reflect.DeepEqual(got, expectedSegments64) {
		t.Fatalf("expected segments64 %#v, got %#v", expectedSegments64, got)
	}
}

func TestVersionSegmentsWithPrefix(t *testing.T) {
	v, err := NewVersion("azure-cli-v1.4.2", WithPrefix("azure-cli-"))
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	expected := []int{1, 4, 2}
	actual := v.Segments()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected: %#v\nactual: %#v", expected, actual)
	}
}

func TestVersionCompare_versionAndSemver(t *testing.T) {
	cases := []struct {
		versionRaw string
		semverRaw  string
		expected   int
	}{
		{"0.0.2", "0.0.2", 0},
		{"1.0.2alpha", "1.0.2-alpha", 0},
		{"v1.2+foo", "v1.2+beta", 0},
		{"v1.2", "v1.2+meta", 0},
		{"1.2", "1.2-beta", 1},
		{"v1.2", "v1.2-beta", 1},
		{"1.2.3", "1.4.5", -1},
		{"v1.2", "v1.2.0.0.1", -1},
		{"v1.0.3-", "v1.0.3", -1},
	}

	for _, tc := range cases {
		ver, err := NewVersion(tc.versionRaw)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		semver, err := NewSemver(tc.semverRaw)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := ver.Compare(semver)
		if actual != tc.expected {
			t.Fatalf(
				"%s <=> %s\nexpected: %d\n actual: %d",
				tc.versionRaw, tc.semverRaw, tc.expected, actual,
			)
		}
	}
}

func TestVersionEqual_nil(t *testing.T) {
	mustVersion := func(v string) *Version {
		ver, err := NewVersion(v)
		if err != nil {
			t.Fatal(err)
		}
		return ver
	}
	cases := []struct {
		leftVersion  *Version
		rightVersion *Version
		expected     bool
	}{
		{mustVersion("1.0.0"), nil, false},
		{nil, mustVersion("1.0.0"), false},
		{nil, nil, true},
	}

	for _, tc := range cases {
		given := tc.leftVersion.Equal(tc.rightVersion)
		if given != tc.expected {
			t.Fatalf("expected Equal to nil to be %t", tc.expected)
		}
	}
}

func TestComparePreReleases(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.2-beta.2", "1.2-beta.2", 0},
		{"1.2-beta.1", "1.2-beta.2", -1},
		{"1.2-beta.2", "1.2-beta.11", -1},
		{"3.2-alpha.1", "3.2-alpha", 1},
		{"1.2-beta.2", "1.2-beta.1", 1},
		{"1.2-beta.11", "1.2-beta.2", 1},
		{"1.2-beta", "1.2-beta.3", -1},
		{"1.2-alpha", "1.2-beta.3", -1},
		{"1.2-beta", "1.2-alpha.3", 1},
		{"3.0-alpha.3", "3.0-rc.1", -1},
		{"3.0-alpha3", "3.0-rc1", -1},
		{"3.0-alpha.1", "3.0-alpha.beta", -1},
		{"5.4-alpha", "5.4-alpha.beta", 1},
		{"v1.2-beta.2", "v1.2-beta.2", 0},
		{"v1.2-beta.1", "v1.2-beta.2", -1},
		{"v3.2-alpha.1", "v3.2-alpha", 1},
		{"v3.2-rc.1-1-g123", "v3.2-rc.2", 1},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.Compare(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s <=> %s\nexpected: %d\nactual: %d",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func TestVersionMetadata(t *testing.T) {
	cases := []struct {
		version  string
		expected string
	}{
		{"1.2.3", ""},
		{"1.2-beta", ""},
		{"1.2.0-x.Y.0", ""},
		{"1.2.0-x.Y.0+metadata", "metadata"},
		{"1.2.0-metadata-1.2.0+metadata~dist", "metadata~dist"},
	}

	for _, tc := range cases {
		v, err := NewVersion(tc.version)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v.Metadata()
		expected := tc.expected
		if actual != expected {
			t.Fatalf("expected: %s\nactual: %s", expected, actual)
		}
	}
}

func TestVersionPrerelease(t *testing.T) {
	cases := []struct {
		version  string
		expected string
	}{
		{"1.2.3", ""},
		{"1.2-beta", "beta"},
		{"1.2.0-x.Y.0", "x.Y.0"},
		{"1.2.0-7.Y.0", "7.Y.0"},
		{"1.2.0-x.Y.0+metadata", "x.Y.0"},
		{"1.2.0-metadata-1.2.0+metadata~dist", "metadata-1.2.0"},
		{"17.03.0-ce", "ce"}, // zero-padded fields
	}

	for _, tc := range cases {
		v, err := NewVersion(tc.version)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v.Prerelease()
		expected := tc.expected
		if actual != expected {
			t.Fatalf("expected: %s\nactual: %s", expected, actual)
		}
	}
}

func TestVersionSegments(t *testing.T) {
	cases := []struct {
		version  string
		expected []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"1.2-beta", []int{1, 2, 0}},
		{"1-x.Y.0", []int{1, 0, 0}},
		{"1.2.0-x.Y.0+metadata", []int{1, 2, 0}},
		{"1.2.0-metadata-1.2.0+metadata~dist", []int{1, 2, 0}},
		{"17.03.0-ce", []int{17, 3, 0}}, // zero-padded fields
	}

	for _, tc := range cases {
		v, err := NewVersion(tc.version)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v.Segments()
		expected := tc.expected
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("expected: %#v\nactual: %#v", expected, actual)
		}
	}
}

func TestVersionSegments64(t *testing.T) {
	cases := []struct {
		version  string
		expected []int64
	}{
		{"1.2.3", []int64{1, 2, 3}},
		{"1.2-beta", []int64{1, 2, 0}},
		{"1-x.Y.0", []int64{1, 0, 0}},
		{"1.2.0-x.Y.0+metadata", []int64{1, 2, 0}},
		{"1.4.9223372036854775807", []int64{1, 4, 9223372036854775807}},
	}

	for _, tc := range cases {
		v, err := NewVersion(tc.version)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v.Segments64()
		expected := tc.expected
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("expected: %#v\nactual: %#v", expected, actual)
		}

		{
			expected := actual[0]
			actual[0]++
			actual = v.Segments64()
			if actual[0] != expected {
				t.Fatalf("Segments64 is mutable")
			}
		}
	}
}

func TestJsonMarshal(t *testing.T) {
	cases := []struct {
		version string
		err     bool
	}{
		{"1.2.3", false},
		{"1.2.0-x.Y.0+metadata", false},
		{"1.2.0-x.Y.0+metadata-width-hyphen", false},
		{"1.2.3-rc1-with-hyphen", false},
		{"1.2.3.4", false},
		{"1.2.0.4-x.Y.0+metadata", false},
		{"1.2.0.4-x.Y.0+metadata-width-hyphen", false},
		{"1.2.0-X-1.2.0+metadata~dist", false},
		{"1.2.3.4-rc1-with-hyphen", false},
		{"1.2.3.4", false},
	}

	for _, tc := range cases {
		v, err1 := NewVersion(tc.version)
		if err1 != nil {
			t.Fatalf("error for version %q: %s", tc.version, err1)
		}

		parsed, err2 := json.Marshal(v)
		if err2 != nil {
			t.Fatalf("error marshaling version %q: %s", tc.version, err2)
		}
		result := string(parsed)
		expected := fmt.Sprintf("%q", tc.version)
		if result != expected && !tc.err {
			t.Fatalf("Error marshaling unexpected marshaled content: result=%q expected=%q", result, expected)
		}
	}
}

func TestJsonUnmarshal(t *testing.T) {
	cases := []struct {
		version string
		err     bool
	}{
		{"1.2.3", false},
		{"1.2.0-x.Y.0+metadata", false},
		{"1.2.0-x.Y.0+metadata-width-hyphen", false},
		{"1.2.3-rc1-with-hyphen", false},
		{"1.2.3.4", false},
		{"1.2.0.4-x.Y.0+metadata", false},
		{"1.2.0.4-x.Y.0+metadata-width-hyphen", false},
		{"1.2.0-X-1.2.0+metadata~dist", false},
		{"1.2.3.4-rc1-with-hyphen", false},
		{"1.2.3.4", false},
	}

	for _, tc := range cases {
		expected, err1 := NewVersion(tc.version)
		if err1 != nil {
			t.Fatalf("err: %s", err1)
		}

		actual := &Version{}
		err2 := json.Unmarshal([]byte(fmt.Sprintf("%q", tc.version)), actual)
		if err2 != nil {
			t.Fatalf("error unmarshaling version: %s", err2)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("error unmarshaling, unexpected object content: actual=%q expected=%q", actual, expected)
		}
	}
}

func TestVersionString(t *testing.T) {
	cases := [][]string{
		{"1.2.3", "1.2.3"},
		{"1.2-beta", "1.2.0-beta"},
		{"1.2.0-x.Y.0", "1.2.0-x.Y.0"},
		{"1.2.0-x.Y.0+metadata", "1.2.0-x.Y.0+metadata"},
		{"1.2.0-metadata-1.2.0+metadata~dist", "1.2.0-metadata-1.2.0+metadata~dist"},
		{"17.03.0-ce", "17.3.0-ce"}, // zero-padded fields
	}

	for _, tc := range cases {
		v, err := NewVersion(tc[0])
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v.String()
		expected := tc[1]
		if actual != expected {
			t.Fatalf("expected: %s\nactual: %s", expected, actual)
		}
		if actual := v.Original(); actual != tc[0] {
			t.Fatalf("expected original: %q\nactual: %q", tc[0], actual)
		}
	}
}

func TestEqual(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"1.2.3", "1.4.5", false},
		{"1.2-beta", "1.2-beta", true},
		{"1.2", "1.1.4", false},
		{"1.2", "1.2-beta", false},
		{"1.2+foo", "1.2+beta", true},
		{"v1.2", "v1.2-beta", false},
		{"v1.2+foo", "v1.2+beta", true},
		{"v1.2.3.4", "v1.2.3.4", true},
		{"v1.2.0.0", "v1.2", true},
		{"v1.2.0.0.1", "v1.2", false},
		{"v1.2", "v1.2.0.0", true},
		{"v1.2", "v1.2.0.0.1", false},
		{"v1.2.0.0", "v1.2.0.0.1", false},
		{"v1.2.3.0", "v1.2.3.4", false},
		{"1.7rc2", "1.7rc1", false},
		{"1.7rc2", "1.7", false},
		{"1.2.0", "1.2.0-X-1.2.0+metadata~dist", false},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.Equal(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s <=> %s\nexpected: %t\nactual: %t",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func TestGreaterThan(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"1.2.3", "1.4.5", false},
		{"1.2-beta", "1.2-beta", false},
		{"1.2", "1.1.4", true},
		{"1.2", "1.2-beta", true},
		{"1.2+foo", "1.2+beta", false},
		{"v1.2", "v1.2-beta", true},
		{"v1.2+foo", "v1.2+beta", false},
		{"v1.2.3.4", "v1.2.3.4", false},
		{"v1.2.0.0", "v1.2", false},
		{"v1.2.0.0.1", "v1.2", true},
		{"v1.2", "v1.2.0.0", false},
		{"v1.2", "v1.2.0.0.1", false},
		{"v1.2.0.0", "v1.2.0.0.1", false},
		{"v1.2.3.0", "v1.2.3.4", false},
		{"1.7rc2", "1.7rc1", true},
		{"1.7rc2", "1.7", false},
		{"1.2.0", "1.2.0-X-1.2.0+metadata~dist", true},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.GreaterThan(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s > %s\nexpected: %t\nactual: %t",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func TestLessThan(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"1.2.3", "1.4.5", true},
		{"1.2-beta", "1.2-beta", false},
		{"1.2", "1.1.4", false},
		{"1.2", "1.2-beta", false},
		{"1.2+foo", "1.2+beta", false},
		{"v1.2", "v1.2-beta", false},
		{"v1.2+foo", "v1.2+beta", false},
		{"v1.2.3.4", "v1.2.3.4", false},
		{"v1.2.0.0", "v1.2", false},
		{"v1.2.0.0.1", "v1.2", false},
		{"v1.2", "v1.2.0.0", false},
		{"v1.2", "v1.2.0.0.1", true},
		{"v1.2.0.0", "v1.2.0.0.1", true},
		{"v1.2.3.0", "v1.2.3.4", true},
		{"1.7rc2", "1.7rc1", false},
		{"1.7rc2", "1.7", true},
		{"1.2.0", "1.2.0-X-1.2.0+metadata~dist", false},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.LessThan(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s < %s\nexpected: %t\nactual: %t",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func TestGreaterThanOrEqual(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"1.2.3", "1.4.5", false},
		{"1.2-beta", "1.2-beta", true},
		{"1.2", "1.1.4", true},
		{"1.2", "1.2-beta", true},
		{"1.2+foo", "1.2+beta", true},
		{"v1.2", "v1.2-beta", true},
		{"v1.2+foo", "v1.2+beta", true},
		{"v1.2.3.4", "v1.2.3.4", true},
		{"v1.2.0.0", "v1.2", true},
		{"v1.2.0.0.1", "v1.2", true},
		{"v1.2", "v1.2.0.0", true},
		{"v1.2", "v1.2.0.0.1", false},
		{"v1.2.0.0", "v1.2.0.0.1", false},
		{"v1.2.3.0", "v1.2.3.4", false},
		{"1.7rc2", "1.7rc1", true},
		{"1.7rc2", "1.7", false},
		{"1.2.0", "1.2.0-X-1.2.0+metadata~dist", true},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.GreaterThanOrEqual(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s >= %s\nexpected: %t\nactual: %t",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func TestLessThanOrEqual(t *testing.T) {
	cases := []struct {
		v1       string
		v2       string
		expected bool
	}{
		{"1.2.3", "1.4.5", true},
		{"1.2-beta", "1.2-beta", true},
		{"1.2", "1.1.4", false},
		{"1.2", "1.2-beta", false},
		{"1.2+foo", "1.2+beta", true},
		{"v1.2", "v1.2-beta", false},
		{"v1.2+foo", "v1.2+beta", true},
		{"v1.2.3.4", "v1.2.3.4", true},
		{"v1.2.0.0", "v1.2", true},
		{"v1.2.0.0.1", "v1.2", false},
		{"v1.2", "v1.2.0.0", true},
		{"v1.2", "v1.2.0.0.1", true},
		{"v1.2.0.0", "v1.2.0.0.1", true},
		{"v1.2.3.0", "v1.2.3.4", true},
		{"1.7rc2", "1.7rc1", false},
		{"1.7rc2", "1.7", true},
		{"1.2.0", "1.2.0-X-1.2.0+metadata~dist", false},
	}

	for _, tc := range cases {
		v1, err := NewVersion(tc.v1)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		v2, err := NewVersion(tc.v2)
		if err != nil {
			t.Fatalf("err: %s", err)
		}

		actual := v1.LessThanOrEqual(v2)
		expected := tc.expected
		if actual != expected {
			t.Fatalf(
				"%s <= %s\nexpected: %t\nactual: %t",
				tc.v1, tc.v2,
				expected, actual)
		}
	}
}

func BenchmarkVersionString(b *testing.B) {
	v, _ := NewVersion("3.4.5-rc1+meta")
	_ = v.String()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = v.String()
	}
}

func BenchmarkCompareVersionV1(b *testing.B) {
	v, _ := NewVersion("3.4.5")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v.Compare(v)
	}
}

func BenchmarkVersionCompareV2(b *testing.B) {
	v, _ := NewVersion("1.2.3")
	o, _ := NewVersion("v1.2.3.4")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v.Compare(o)
	}
}
