/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package ec2

import (
	"context"
	"fmt"
	"testing"

	ec2imds "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	ec2service "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/stretchr/testify/assert"
)

type fakeEC2Metadata struct {
	metadata map[string]string
}

type fakeEC2Tags struct {
	tags []ec2types.TagDescription
}

func (e *fakeEC2Metadata) FetchMetadata(path string) (string, error) {
	value, found := e.metadata[path]
	if !found {
		return "", fmt.Errorf("%s not found", path)
	}

	return value, nil
}

func (e *fakeEC2Metadata) FetchInstanceIdentityDocument() (
	ec2imds.InstanceIdentityDocument, error) {
	return ec2imds.InstanceIdentityDocument{}, nil
}

func (e *fakeEC2Tags) DescribeTags(context.Context, *ec2service.DescribeTagsInput,
	...func(*ec2service.Options)) (*ec2service.DescribeTagsOutput, error) {
	return &ec2service.DescribeTagsOutput{Tags: e.tags}, nil
}

func TestAddMetadata(t *testing.T) {
	ec2MetadataClient = &fakeEC2Metadata{
		metadata: map[string]string{
			"ami-id":              "ami-1234",
			"ami-manifest-path":   "(unknown)",
			"ancestor-ami-ids":    "ami-2345",
			"hostname":            "ec2.internal",
			"instance-id":         "i-abcdef",
			"instance-type":       "m5.large",
			"instance-life-cycle": "on-demand",
			"local-hostname":      "compute-internal",
			"local-ipv4":          "172.16.1.1",
			"kernel-id":           "aki-1419e57b",
			"mac":                 "0e:0f:00:01:02:03",
			"profile":             "default-hvm",
			"public-hostname":     "ec2-10-eu-west-1.compute.amazonaws.com",
			"public-ipv4":         "1.2.3.4",
			"product-codes":       "foobarbaz",
			"security-groups":     "default\nlaunch-wizard-1",

			"placement/availability-zone":    "us-east-2c",
			"placement/availability-zone-id": "use2-az3",
			"placement/region":               "us-east-2",

			"network/interfaces/macs/":                              "123\n456\n789",
			"network/interfaces/macs/123/device-number":             "1",
			"network/interfaces/macs/456/local-ipv4s":               "1.2.3.4\n5.6.7.8",
			"network/interfaces/macs/456/public-ipv4s":              "9.9.9.9\n8.8.8.8",
			"network/interfaces/macs/789/public-ipv4s":              "4.3.2.1",
			"network/interfaces/macs/789/ipv4-associations/":        "7.7.7.7\n4.4.4.4",
			"network/interfaces/macs/789/ipv4-associations/7.7.7.7": "77.77.77.77",
			"network/interfaces/macs/789/ipv4-associations/4.4.4.4": "44.44.44.44",
		},
	}

	ec2Client = &fakeEC2Tags{
		tags: []ec2types.TagDescription{
			{
				Key:   stringPtr("foo"),
				Value: stringPtr("bar"),
			},
			{
				Key:   stringPtr("baz"),
				Value: stringPtr("value1-value2"),
			},
		},
	}

	result := make(map[string]string)
	AddMetadata(result)

	expected := map[string]string{
		"cloud.provider":          "aws",
		"cloud.region":            "us-east-2",
		"host.type":               "m5.large",
		"ec2.ami_id":              "ami-1234",
		"ec2.ami_manifest_path":   "(unknown)",
		"ec2.ancestor_ami_ids":    "ami-2345",
		"ec2.hostname":            "ec2.internal",
		"ec2.instance_id":         "i-abcdef",
		"ec2.instance_type":       "m5.large",
		"ec2.instance_life_cycle": "on-demand",
		"ec2.local_hostname":      "compute-internal",
		"ec2.local_ipv4":          "172.16.1.1",
		"ec2.kernel_id":           "aki-1419e57b",
		"ec2.mac":                 "0e:0f:00:01:02:03",
		"ec2.profile":             "default-hvm",
		"ec2.public_hostname":     "ec2-10-eu-west-1.compute.amazonaws.com",
		"ec2.public_ipv4":         "1.2.3.4",
		"ec2.product_codes":       "foobarbaz",
		"ec2.security_groups":     "default\nlaunch-wizard-1",

		"ec2.placement.availability_zone":    "us-east-2c",
		"ec2.placement.availability_zone_id": "use2-az3",
		"ec2.placement.region":               "us-east-2",

		"ec2.network.interfaces.macs.123.device_number":             "1",
		"ec2.network.interfaces.macs.456.local_ipv4s":               "1.2.3.4\n5.6.7.8",
		"ec2.network.interfaces.macs.456.public_ipv4s":              "9.9.9.9\n8.8.8.8",
		"ec2.network.interfaces.macs.789.ipv4_associations.4.4.4.4": "44.44.44.44",
		"ec2.network.interfaces.macs.789.ipv4_associations.7.7.7.7": "77.77.77.77",
		"ec2.network.interfaces.macs.789.public_ipv4s":              "4.3.2.1",

		"ec2.tags.foo":           "bar",
		"ec2.tags.baz":           "value1-value2",
		"instance.private_ipv4s": "1.2.3.4,5.6.7.8",
		"instance.public_ipv4s":  "9.9.9.9,8.8.8.8,4.3.2.1",
	}

	assert.Equal(t, expected, result)
}
