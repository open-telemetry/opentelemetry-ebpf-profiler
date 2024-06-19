/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package ec2

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	ec2imds "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"

	ec2service "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/elastic/otel-profiling-agent/hostmetadata/instance"
)

// ec2MetadataIface is an interface for the EC2 metadata service.
// Its purpose is to allow faking the implementation in unit tests.
type ec2MetadataIface interface {
	FetchMetadata(string) (string, error)
	FetchInstanceIdentityDocument() (ec2imds.InstanceIdentityDocument, error)
}

type ec2Iface interface {
	DescribeTags(context.Context, *ec2service.DescribeTagsInput,
		...func(*ec2service.Options)) (*ec2service.DescribeTagsOutput, error)
}

// ec2MetadataClient can be nil if it cannot be built.
var ec2MetadataClient, _ = buildMetadataClient()

// ec2Client is lazily initialized inside addTags()
var ec2Client ec2Iface

const ec2Prefix = "ec2:"

type ec2MetadataWrapper struct {
	*ec2imds.Client
}

func (c *ec2MetadataWrapper) FetchMetadata(input string) (string, error) {
	metadataOutput, err := c.GetMetadata(context.Background(),
		&ec2imds.GetMetadataInput{
			Path: input,
		})
	if err != nil {
		return "", err
	}
	valueBytes, err := io.ReadAll(metadataOutput.Content)
	if err != nil {
		return "", err
	}
	return string(valueBytes), nil
}

func (c *ec2MetadataWrapper) FetchInstanceIdentityDocument() (
	ec2imds.InstanceIdentityDocument, error) {
	doc, err := c.GetInstanceIdentityDocument(context.Background(), nil)
	if err != nil {
		return ec2imds.InstanceIdentityDocument{}, err
	}
	return doc.InstanceIdentityDocument, nil
}

func buildMetadataClient() (ec2MetadataIface, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Errorf("Failed to create default config for AWS: %v", err)
		return nil, err
	}

	return &ec2MetadataWrapper{ec2imds.NewFromConfig(cfg)}, nil
}

func buildClient() (ec2Iface, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	return ec2service.NewFromConfig(cfg), nil
}

func getMetadataForKeys(prefix string, suffix []string, result map[string]string) {
	for i := range suffix {
		keyPath := path.Join(prefix, suffix[i])
		value, err := ec2MetadataClient.FetchMetadata(keyPath)

		// This is normal, as some keys do not exist
		if err != nil {
			log.Debugf("Unable to get metadata key: %s: %v", keyPath, err)
			continue
		}
		result[ec2Prefix+keyPath] = value
	}
}

// list returns the list of keys at the given instance metadata service path.
func list(urlPath string) ([]string, error) {
	value, err := ec2MetadataClient.FetchMetadata(urlPath)

	if err != nil {
		return nil, fmt.Errorf("unable to list %v: %s", urlPath, err)
	}

	return instance.Enumerate(value), nil
}

func stringPtr(v string) *string {
	return &v
}

// addTags retrieves and adds EC2 instance tags into the provided map.
// Tags are added separately, prefixed with 'ec2:tags/{key}' for each tag key.
// In order for this operation to succeed, the instance needs to have an
// IAM role assigned, with a policy that grants ec2:DescribeTags.
func addTags(instanceID string, result map[string]string) {
	if ec2Client == nil {
		var err error
		ec2Client, err = buildClient()
		if err != nil {
			log.Warnf("EC2 client couldn't be created, skipping tag collection")
			return
		}
	}

	descTagsOut, err := ec2Client.DescribeTags(context.Background(),
		&ec2service.DescribeTagsInput{
			Filters: []ec2types.Filter{
				{
					Name: stringPtr("resource-id"),
					Values: []string{
						instanceID,
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

	var instanceID string

	if idDoc, err := ec2MetadataClient.FetchInstanceIdentityDocument(); err == nil {
		instanceID = idDoc.InstanceID
	} else {
		log.Warnf("EC2 metadata could not be collected: %v", err)
		return
	}

	result[instance.KeyCloudProvider] = "aws"

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

	addCloudRegion(result)
	addHostType(result)

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

		assocsPath := macPath + "ipv4-associations/"
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
	addTags(instanceID, result)
}

func addCloudRegion(result map[string]string) {
	if region, ok := result[ec2Prefix+"placement/region"]; ok {
		result[instance.KeyCloudRegion] = region
	}
}

func addHostType(result map[string]string) {
	if instanceType, ok := result[ec2Prefix+"instance-type"]; ok {
		result[instance.KeyHostType] = instanceType
	}
}
