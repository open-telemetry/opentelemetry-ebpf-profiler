/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

//nolint:lll
package gce

import (
	"fmt"
	"testing"

	"github.com/elastic/otel-profiling-agent/hostmetadata/instance"

	"github.com/stretchr/testify/assert"
)

type fakeGCEMetadata struct {
	tags     []string
	metadata map[string]string
}

func (e *fakeGCEMetadata) Get(path string) (string, error) {
	res, found := e.metadata[path]
	if !found {
		return "", fmt.Errorf("%s not found", path)
	}
	return res, nil
}

func (e *fakeGCEMetadata) InstanceTags() ([]string, error) {
	return e.tags, nil
}

func (e *fakeGCEMetadata) OnGCE() bool {
	return true
}

func TestAddMetadata(t *testing.T) {
	gceClient = &fakeGCEMetadata{
		tags: []string{"foo", "bar", "baz"},
		metadata: map[string]string{
			"instance/id":                                                "1234",
			"instance/cpu-platform":                                      "Intel Cascade Lake",
			"instance/machine-type":                                      "projects/123456/machineTypes/test-n2-custom-4-10240",
			"instance/name":                                              "gke-mirror-cluster-api",
			"instance/description":                                       "test description",
			"instance/hostname":                                          "barbaz",
			"instance/zone":                                              "projects/123456/zones/us-east1-c",
			"instance/network-interfaces/":                               "0\n1\n2",
			"instance/network-interfaces/0/ip":                           "1.1.1.1",
			"instance/network-interfaces/0/network":                      "networks/default",
			"instance/network-interfaces/0/subnetmask":                   "255.255.240.0",
			"instance/network-interfaces/1/gateway":                      "22.22.22.22",
			"instance/network-interfaces/2/mac":                          "3:3:3",
			"instance/network-interfaces/2/access-configs/":              "0\n1\n2",
			"instance/network-interfaces/2/access-configs/0/external-ip": "7.7.7.7",
			"instance/network-interfaces/2/access-configs/1/external-ip": "8.8.8.8",
			"instance/network-interfaces/2/access-configs/2/external-ip": "9.9.9.9",
			"instance/image":                                             "gke-node-images/global",
		},
	}
	result := make(map[string]string)
	AddMetadata(result)

	expectedResult := map[string]string{
		"cloud.provider":                               "gcp",
		"cloud.region":                                 "us-east1",
		"host.type":                                    "test-n2-custom-4-10240",
		"gce.instance.id":                              "1234",
		"gce.instance.cpu_platform":                    "Intel Cascade Lake",
		"gce.instance.machine_type":                    "projects/123456/machineTypes/test-n2-custom-4-10240",
		"gce.instance.name":                            "gke-mirror-cluster-api",
		"gce.instance.description":                     "test description",
		"gce.instance.network_interfaces.0.ip":         "1.1.1.1",
		"gce.instance.network_interfaces.0.network":    "networks/default",
		"gce.instance.network_interfaces.0.subnetmask": "255.255.240.0",
		"gce.instance.network_interfaces.1.gateway":    "22.22.22.22",
		"gce.instance.network_interfaces.2.access_configs.0.external_ip": "7.7.7.7",
		"gce.instance.network_interfaces.2.access_configs.1.external_ip": "8.8.8.8",
		"gce.instance.network_interfaces.2.access_configs.2.external_ip": "9.9.9.9",
		"gce.instance.network_interfaces.2.mac":                          "3:3:3",
		"gce.instance.hostname":                                          "barbaz",
		"gce.instance.zone":                                              "projects/123456/zones/us-east1-c",
		"gce.instance.image":                                             "gke-node-images/global",
		"gce.instance.tags":                                              "foo;bar;baz",
		"instance.private_ipv4s":                                         "1.1.1.1",
		"instance.public_ipv4s":                                          "7.7.7.7,8.8.8.8,9.9.9.9",
	}

	assert.Equal(t, expectedResult, result)
}

func TestAddCloudRegion(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "empty",
			value:    "",
			expected: "",
		},
		{
			name:     "slash only",
			value:    "/",
			expected: "",
		},
		{
			name:     "no region",
			value:    "projects/123456789/zones/",
			expected: "",
		},
		{
			name:     "no dash",
			value:    "projects/123456789/zones/europewest1",
			expected: "europewest1",
		},
		{
			name:     "one dash",
			value:    "projects/123456789/zones/europe-west1",
			expected: "europe-west1",
		},
		{
			name:     "two dashes",
			value:    "projects/123456789/zones/europe-west1-b",
			expected: "europe-west1",
		},
		{
			name:     "three dashes",
			value:    "projects/123456789/zones/europe-west1-b-c",
			expected: "europe-west1",
		},
	}

	for _, test := range tests {
		result := make(map[string]string)

		result[gcePrefix+"instance.zone"] = test.value
		addCloudRegion(result)

		expectedResult := map[string]string{
			gcePrefix + "instance.zone": test.value,
		}
		if test.expected != "" {
			expectedResult[instance.KeyCloudRegion] = test.expected
		}
		assert.Equal(t, expectedResult, result)
	}
}

func TestAddHostType(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "empty",
			value:    "",
			expected: "",
		},
		{
			name:     "slash only",
			value:    "/",
			expected: "",
		},
		{
			name:     "no region",
			value:    "projects/123456/machineTypes/",
			expected: "",
		},
		{
			name:     "no dash",
			value:    "projects/123456/machineTypes/n1-standard-1",
			expected: "n1-standard-1",
		},
	}

	for _, test := range tests {
		result := make(map[string]string)

		result[gcePrefix+"instance.machine_type"] = test.value
		addHostType(result)

		expectedResult := map[string]string{
			gcePrefix + "instance.machine_type": test.value,
		}
		if test.expected != "" {
			expectedResult[instance.KeyHostType] = test.expected
		}
		assert.Equal(t, expectedResult, result)
	}
}
