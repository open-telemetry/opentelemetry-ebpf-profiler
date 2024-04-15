/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package ec2

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/google/go-cmp/cmp"
)

type fakeEC2Metadata struct {
	metadata map[string]string
}

type fakeEC2Tags struct {
	tags []*ec2.TagDescription
}

func (e *fakeEC2Metadata) GetMetadata(path string) (string, error) {
	value, found := e.metadata[path]
	if !found {
		return "", fmt.Errorf("%s not found", path)
	}

	return value, nil
}

func (e *fakeEC2Metadata) GetInstanceIdentityDocument() (ec2metadata.EC2InstanceIdentityDocument,
	error) {
	return ec2metadata.EC2InstanceIdentityDocument{}, nil
}

func (e *fakeEC2Tags) DescribeTags(_ *ec2.DescribeTagsInput,
) (*ec2.DescribeTagsOutput, error) {
	return &ec2.DescribeTagsOutput{Tags: e.tags}, nil
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
		tags: []*ec2.TagDescription{
			{
				Key:   aws.String("foo"),
				Value: aws.String("bar"),
			},
			{
				Key:   aws.String("baz"),
				Value: aws.String("value1-value2"),
			},
		},
	}

	result := make(map[string]string)
	AddMetadata(result)

	expected := map[string]string{
		"ec2:ami-id":              "ami-1234",
		"ec2:ami-manifest-path":   "(unknown)",
		"ec2:ancestor-ami-ids":    "ami-2345",
		"ec2:hostname":            "ec2.internal",
		"ec2:instance-id":         "i-abcdef",
		"ec2:instance-type":       "m5.large",
		"ec2:instance-life-cycle": "on-demand",
		"ec2:local-hostname":      "compute-internal",
		"ec2:local-ipv4":          "172.16.1.1",
		"ec2:kernel-id":           "aki-1419e57b",
		"ec2:mac":                 "0e:0f:00:01:02:03",
		"ec2:profile":             "default-hvm",
		"ec2:public-hostname":     "ec2-10-eu-west-1.compute.amazonaws.com",
		"ec2:public-ipv4":         "1.2.3.4",
		"ec2:product-codes":       "foobarbaz",
		"ec2:security-groups":     "default\nlaunch-wizard-1",

		"ec2:placement/availability-zone":    "us-east-2c",
		"ec2:placement/availability-zone-id": "use2-az3",
		"ec2:placement/region":               "us-east-2",

		"ec2:network/interfaces/macs/123/device-number":             "1",
		"ec2:network/interfaces/macs/456/local-ipv4s":               "1.2.3.4\n5.6.7.8",
		"ec2:network/interfaces/macs/456/public-ipv4s":              "9.9.9.9\n8.8.8.8",
		"ec2:network/interfaces/macs/789/ipv4-associations/4.4.4.4": "44.44.44.44",
		"ec2:network/interfaces/macs/789/ipv4-associations/7.7.7.7": "77.77.77.77",
		"ec2:network/interfaces/macs/789/public-ipv4s":              "4.3.2.1",

		"ec2:tags/foo":           "bar",
		"ec2:tags/baz":           "value1-value2",
		"instance:private-ipv4s": "1.2.3.4,5.6.7.8",
		"instance:public-ipv4s":  "9.9.9.9,8.8.8.8,4.3.2.1",
	}

	if diff := cmp.Diff(expected, result); diff != "" {
		t.Fatalf("Metadata mismatch (-want +got):\n%s", diff)
	}
}
