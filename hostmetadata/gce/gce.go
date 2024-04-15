/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package gce

import (
	"fmt"
	"path"
	"strings"

	"github.com/elastic/otel-profiling-agent/hostmetadata/instance"
	log "github.com/sirupsen/logrus"
)

const gcePrefix = "gce:"

var gceClient gceMetadataIface = &gceMetadataClient{}

// list returns the list of keys at the given instance metadata service path.
func list(urlPath string) ([]string, error) {
	resp, err := gceClient.Get(urlPath)
	if err != nil {
		return nil, fmt.Errorf("unable to list %v: %v", urlPath, err)
	}

	return instance.Enumerate(resp), nil
}

func getMetadataForKeys(prefix string, suffix []string, result map[string]string) {
	for i := range suffix {
		keyPath := path.Join(prefix, suffix[i])
		value, err := gceClient.Get(keyPath)
		if err != nil {
			// Not all keys are expected to exist
			log.Debugf("Unable to get metadata key %s: %v", keyPath, err)
			continue
		}
		result[gcePrefix+keyPath] = value
	}
}

// AddMetadata gathers a subset of GCE instance metadata, and adds it to the result map.
// This is safe to call even if the instance isn't running on GCE.
// The added keys are the metadata path in the metadata service, prefixed with 'gce:'.
// Synthetic metadata is also added, prefixed with 'instance:'.
// Failures (missing keys, etc) are logged and ignored.
func AddMetadata(result map[string]string) {
	if !gceClient.OnGCE() {
		return
	}

	// Get metadata under instance/
	getMetadataForKeys("instance/", []string{
		"id",
		"cpu-platform",
		"description",
		"hostname",
		"image",
		"machine-type",
		"name",
		"zone",
	}, result)

	// Get the tags
	tags, err := gceClient.InstanceTags()
	if err != nil {
		log.Warnf("Unable to retrieve tags: %v", err)
	} else if len(tags) > 0 {
		// GCE tags can only contain lowercase letters, numbers, and hyphens,
		// therefore ';' is safe to use as a separator.
		result[gcePrefix+"instance/tags"] = strings.Join(tags, ";")
	}

	ifaces, err := list("instance/network-interfaces/")
	if err != nil {
		log.Warnf("Unable to list network interfaces: %v", err)
	}

	// Used to temporarily hold synthetic metadata
	ipAddrs := map[string][]string{
		instance.KeyPublicIPV4s:  make([]string, 0),
		instance.KeyPrivateIPV4s: make([]string, 0),
	}

	// Get metadata under instance/network-interfaces/*/
	for _, iface := range ifaces {
		interfacePath := fmt.Sprintf("instance/network-interfaces/%s/", iface)

		getMetadataForKeys(interfacePath, []string{
			"ip",
			"gateway",
			"mac",
			"network",
			"subnetmask",
		}, result)

		if ip, ok := result[gcePrefix+interfacePath+"ip"]; ok {
			ipAddrs[instance.KeyPrivateIPV4s] = append(ipAddrs[instance.KeyPrivateIPV4s], ip)
		}

		accessConfigs, err := list(fmt.Sprintf("%saccess-configs/", interfacePath))
		if err != nil {
			// There might not be any access configurations
			log.Debugf("Unable to list access configurations: %v", err)
		}

		// Get metadata under instance/network-interfaces/*/access-configs/*/
		// (this is where we can get public IP, if there is one)
		for _, accessConfig := range accessConfigs {
			accessConfigPath := path.Join(interfacePath,
				fmt.Sprintf("access-configs/%s", accessConfig))

			getMetadataForKeys(accessConfigPath, []string{"external-ip"}, result)
			if ip, ok := result[gcePrefix+accessConfigPath+"/external-ip"]; ok {
				ipAddrs[instance.KeyPublicIPV4s] = append(ipAddrs[instance.KeyPublicIPV4s], ip)
			}
		}
	}

	instance.AddToResult(ipAddrs, result)
}
