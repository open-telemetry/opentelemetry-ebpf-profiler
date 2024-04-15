/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package gce

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
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
			"instance/machine-type":                                      "test-n2-custom-4-10240",
			"instance/name":                                              "gke-mirror-cluster-api",
			"instance/description":                                       "test description",
			"instance/hostname":                                          "barbaz",
			"instance/zone":                                              "zones/us-east1-c",
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
		"gce:instance/id":                                                "1234",
		"gce:instance/cpu-platform":                                      "Intel Cascade Lake",
		"gce:instance/machine-type":                                      "test-n2-custom-4-10240",
		"gce:instance/name":                                              "gke-mirror-cluster-api",
		"gce:instance/description":                                       "test description",
		"gce:instance/network-interfaces/0/ip":                           "1.1.1.1",
		"gce:instance/network-interfaces/0/network":                      "networks/default",
		"gce:instance/network-interfaces/0/subnetmask":                   "255.255.240.0",
		"gce:instance/network-interfaces/1/gateway":                      "22.22.22.22",
		"gce:instance/network-interfaces/2/access-configs/0/external-ip": "7.7.7.7",
		"gce:instance/network-interfaces/2/access-configs/1/external-ip": "8.8.8.8",
		"gce:instance/network-interfaces/2/access-configs/2/external-ip": "9.9.9.9",
		"gce:instance/network-interfaces/2/mac":                          "3:3:3",
		"gce:instance/hostname":                                          "barbaz",
		"gce:instance/zone":                                              "zones/us-east1-c",
		"gce:instance/image":                                             "gke-node-images/global",
		"gce:instance/tags":                                              "foo;bar;baz",
		"instance:private-ipv4s":                                         "1.1.1.1",
		"instance:public-ipv4s":                                          "7.7.7.7,8.8.8.8,9.9.9.9",
	}

	if diff := cmp.Diff(expectedResult, result); diff != "" {
		t.Fatalf("Metadata mismatch (-want +got):\n%s", diff)
	}
}
