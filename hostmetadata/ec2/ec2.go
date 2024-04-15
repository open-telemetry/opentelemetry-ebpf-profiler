/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package ec2

import (
	"fmt"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/elastic/otel-profiling-agent/hostmetadata/instance"
	log "github.com/sirupsen/logrus"
)

// ec2MetadataIface is an interface for the EC2 metadata service.
// Its purpose is to allow faking the implementation in unit tests.
type ec2MetadataIface interface {
	GetMetadata(string) (string, error)
	GetInstanceIdentityDocument() (ec2metadata.EC2InstanceIdentityDocument, error)
}

type ec2Iface interface {
	DescribeTags(*ec2.DescribeTagsInput) (*ec2.DescribeTagsOutput, error)
}

// ec2MetadataClient can be nil if it cannot be built.
var ec2MetadataClient = buildMetadataClient()

// ec2Client is lazily initialized inside addTags()
var ec2Client ec2Iface

const ec2Prefix = "ec2:"

func buildMetadataClient() ec2MetadataIface {
	se := session.Must(session.NewSession())
	// Retries make things slow needlessly. Since the metadata service runs on the same network
	// link, no need to worry about an unreliable network.
	// We collect metadata often enough for errors to be tolerable.
	return ec2metadata.New(se, aws.NewConfig().WithMaxRetries(0))
}

func buildClient(region string) ec2Iface {
	se := session.Must(session.NewSession())
	return ec2.New(se, aws.NewConfig().WithMaxRetries(0).WithRegion(region))
}

// awsErrorMessage rewrites a 404 AWS error message to reduce verbosity.
// If the error is not a 404, the full error string is returned.
func awsErrorMessage(err error) string {
	if awsErr, ok := err.(awserr.RequestFailure); ok {
		if awsErr.StatusCode() == 404 {
			return "not found"
		}
	}
	return err.Error()
}

func getMetadataForKeys(prefix string, suffix []string, result map[string]string) {
	for i := range suffix {
		keyPath := path.Join(prefix, suffix[i])
		value, err := ec2MetadataClient.GetMetadata(keyPath)

		// This is normal, as some keys do not exist
		if err != nil {
			log.Debugf("Unable to get metadata key: %s: %s", keyPath, awsErrorMessage(err))
			continue
		}
		result[ec2Prefix+keyPath] = value
	}
}

// list returns the list of keys at the given instance metadata service path.
func list(urlPath string) ([]string, error) {
	value, err := ec2MetadataClient.GetMetadata(urlPath)

	if err != nil {
		return nil, fmt.Errorf("unable to list %v: %s", urlPath, awsErrorMessage(err))
	}

	return instance.Enumerate(value), nil
}

// addTags retrieves and adds EC2 instance tags into the provided map.
// Tags are added separately, prefixed with 'ec2:tags/{key}' for each tag key.
// In order for this operation to succeed, the instance needs to have an
// IAM role assigned, with a policy that grants ec2:DescribeTags.
func addTags(region, instanceID string, result map[string]string) {
	if ec2Client == nil {
		ec2Client = buildClient(region)
		if ec2Client == nil {
			log.Warnf("EC2 client couldn't be created, skipping tag collection")
			return
		}
	}

	descTagsOut, err := ec2Client.DescribeTags(
		&ec2.DescribeTagsInput{
			Filters: []*ec2.Filter{
				{
					Name: aws.String("resource-id"),
					Values: []*string{
						aws.String(instanceID),
					},
				},
			},
		})

	if err != nil {
		log.Warnf("Unable to retrieve tags: %v", err)
		return
	}

	// EC2 tags have no character restrictions, therefore we store each key:value separately
	for _, tag := range descTagsOut.Tags {
		result[fmt.Sprintf("%stags/%s", ec2Prefix, *tag.Key)] = *tag.Value
	}
}

// AddMetadata adds metadata from the EC2 metadata service into the provided map.
// This is safe to call even if the instance isn't running on EC2.
// Added keys are the metadata path in the metadata service, prefixed with 'ec2:'.
// Instance tags are stored separately, prefixed with 'ec2:tags/{key}' for each tag key.
// Synthetic metadata is also added, prefixed with 'instance:'.
// Failures (missing keys, etc) are logged and ignored.
func AddMetadata(result map[string]string) {
	if ec2MetadataClient == nil {
		log.Warnf("EC2 metadata client couldn't be created, skipping metadata collection")
		return
	}

	var region string
	var instanceID string

	if idDoc, err := ec2MetadataClient.GetInstanceIdentityDocument(); err == nil {
		region = idDoc.Region
		instanceID = idDoc.InstanceID
	} else {
		log.Warnf("EC2 metadata could not be collected: %v", err)
		return
	}

	getMetadataForKeys("", []string{
		"ami-id",
		"ami-manifest-path",
		"ancestor-ami-ids",
		"hostname",
		"instance-id",
		"instance-type",
		"instance-life-cycle",
		"local-hostname",
		"local-ipv4",
		"kernel-id",
		"mac",
		"profile", // virtualization profile
		"public-hostname",
		"public-ipv4",
		"product-codes",
		"security-groups",
	}, result)

	getMetadataForKeys("placement", []string{
		"availability-zone",
		"availability-zone-id",
		"region",
	}, result)

	macs, err := list("network/interfaces/macs/")
	if err != nil {
		log.Warnf("Unable to list network interfaces: %v", err)
	}

	// Used to temporarily hold synthetic metadata
	ipAddrs := map[string][]string{
		instance.KeyPublicIPV4s:  make([]string, 0),
		instance.KeyPrivateIPV4s: make([]string, 0),
	}

	for _, mac := range macs {
		macPath := fmt.Sprintf("network/interfaces/macs/%s/", mac)
		getMetadataForKeys(macPath, []string{
			"device-number",
			"interface-id",
			"local-hostname",
			"local-ipv4s",
			"mac",
			"owner-id",
			"public-hostname",
			"public-ipv4s",
			"security-group-ids",
			"security-groups",
			"subnet-id",
			"subnet-ipv4-cidr-block",
			"vpc-id",
			"vpc-ipv4-cidr-block",
			"vpc-ipv4-cidr-blocks",
		}, result)

		if ips, ok := result[ec2Prefix+macPath+"public-ipv4s"]; ok {
			ipAddrs[instance.KeyPublicIPV4s] = append(ipAddrs[instance.KeyPublicIPV4s],
				strings.ReplaceAll(ips, "\n", ","))
		}

		if ips, ok := result[ec2Prefix+macPath+"local-ipv4s"]; ok {
			ipAddrs[instance.KeyPrivateIPV4s] = append(ipAddrs[instance.KeyPrivateIPV4s],
				strings.ReplaceAll(ips, "\n", ","))
		}

		assocsPath := fmt.Sprintf("%sipv4-associations/", macPath)
		assocs, err := list(assocsPath)
		if err != nil {
			// Nothing to worry about: there might not be any associations
			log.Debugf("Unable to list ipv4 associations: %v", err)
		}
		for _, assoc := range assocs {
			getMetadataForKeys(assocsPath, []string{assoc}, result)
		}
	}

	instance.AddToResult(ipAddrs, result)
	addTags(region, instanceID, result)
}
