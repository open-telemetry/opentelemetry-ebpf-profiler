/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/elastic/otel-profiling-agent/hostmetadata/instance"
	log "github.com/sirupsen/logrus"
)

const azurePrefix = "azure:"

// Compute stores computing related metadata information of an Azure instance.
type Compute struct {
	Environment    string `json:"azEnvironment"`
	Location       string `json:"location"`
	Name           string `json:"name"`
	VMID           string `json:"vmId"`
	Tags           string `json:"tags"`
	Zone           string `json:"zone"`
	VMSize         string `json:"vmSize"`
	Offer          string `json:"offer"`
	OsType         string `json:"osType"`
	Publisher      string `json:"publisher"`
	Sku            string `json:"sku"`
	Version        string `json:"version"`
	SubscriptionID string `json:"subscriptionId"`
}

// Network stores the network related metadata information of an Azure instance.
type Network struct {
	Interface []IPInterface `json:"interface"`
}

// IPInterface stores layer 2 and 3 metadata
type IPInterface struct {
	IPv4 IPInfo `json:"ipv4"`
	IPv6 IPInfo `json:"ipv6"`
	Mac  string `json:"macAddress"`
}

// IPInfo holds the available IP information for a particular IP family on an interface.
type IPInfo struct {
	Addr   []IPAddr   `json:"ipAddress"`
	Subnet []IPSubnet `json:"subnet"`
}

// IPAddr holds the private and public IP address of an interface.
type IPAddr struct {
	PublicIP  string `json:"publicIpAddress"`
	PrivateIP string `json:"privateIpAddress"`
}

// IPSubnet stores the subnet related information to an IPAddr.
type IPSubnet struct {
	Address string `json:"address"`
	Prefix  string `json:"prefix"`
}

// IMDS holds the metadata information of a Azure instance.
type IMDS struct {
	Compute Compute `json:"compute"`
	Network Network `json:"network"`
}

// AddMetadata adds metadata from the Azure metadata service into the provided map.
// This is safe to call even if the instance isn't running on Azure.
// Added keys are the metadata path in the metadata service, prefixed with 'azure:'.
// Synthetic metadata is also added, prefixed with 'instance:'.
// Failures (missing keys, etc) are logged and ignored.
//
// We extract the Azure metadata according to the information at
// nolint:lll
// https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=linux#endpoint-categories
//
// - 169.254.169.254 is the standard endpoint for the instance metadata service in all clouds.
// One of the few things all cloud providers agree upon
// - 169.254.0.0/16 addresses are link-local IP addresses (traffic is non-routable, and won't
// leave the local network segment). In practice, the http server that actually answers the
// requests lives inside the instance hardware
// - There is no TLS with the metadata service. Both trust and data protection are provided by
// the non-routability of the traffic (requests are handled locally, inside boundaries that are
// implicitly trusted by the user). If that http server goes down, someone working at the cloud
// provider will get paged.
func AddMetadata(result map[string]string) {
	var PTransport = &http.Transport{Proxy: nil}

	client := http.Client{Transport: PTransport}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/metadata/instance", http.NoBody)
	if err != nil {
		log.Errorf("Failed to create Azure metadata query: %v", err)
		return
	}
	req.Header.Add("Metadata", "True")

	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("api-version", "2020-09-01")
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Warnf("Azure metadata client couldn't be created, skipping metadata collection")
		return
	}
	defer resp.Body.Close()

	var imds IMDS
	if err := json.NewDecoder(resp.Body).Decode(&imds); err != nil {
		log.Errorf("Failed to parse Azure metadata: %v", err)
		return
	}

	populateResult(result, &imds)
}

// populateResult converts the given answer from Azure in imds into
// our internal representation in result.
func populateResult(result map[string]string, imds *IMDS) {
	v := reflect.ValueOf(imds.Compute)
	t := reflect.TypeOf(imds.Compute)
	for i := 0; i < v.NumField(); i++ {
		fieldName := t.Field(i).Name
		fieldValue := v.Field(i).Interface().(string)
		if fieldValue == "" {
			// Don't store empty values.
			continue
		}
		result[azurePrefix+"compute/"+strings.ToLower(fieldName)] = fieldValue
	}

	// Used to temporarily hold synthetic metadata
	ipAddrs := map[string][]string{
		instance.KeyPrivateIPV4s: make([]string, 0),
		instance.KeyPrivateIPV6s: make([]string, 0),
		instance.KeyPublicIPV4s:  make([]string, 0),
		instance.KeyPublicIPV6s:  make([]string, 0),
	}

	for i, iface := range imds.Network.Interface {
		result[azurePrefix+"network/interface/"+fmt.Sprintf("%d/macaddress", i)] = iface.Mac
		for j, ipv4 := range iface.IPv4.Addr {
			keyPrefix := azurePrefix + "network/interface/" +
				fmt.Sprintf("%d/ipv4/ipaddress/%d/", i, j)
			if ipv4.PrivateIP != "" {
				result[keyPrefix+"privateipaddress"] = ipv4.PrivateIP
				ipAddrs[instance.KeyPrivateIPV4s] = append(ipAddrs[instance.KeyPrivateIPV4s],
					ipv4.PrivateIP)
			}
			if ipv4.PublicIP != "" {
				result[keyPrefix+"publicipaddress"] = ipv4.PublicIP
				ipAddrs[instance.KeyPublicIPV4s] = append(ipAddrs[instance.KeyPublicIPV4s],
					ipv4.PublicIP)
			}
		}
		for j, netv4 := range iface.IPv4.Subnet {
			keyPrefix := azurePrefix + "network/interface/" +
				fmt.Sprintf("%d/ipv4/subnet/%d/", i, j)
			if netv4.Address != "" {
				result[keyPrefix+"address"] = netv4.Address
			}
			if netv4.Prefix != "" {
				result[keyPrefix+"prefix"] = netv4.Prefix
			}
		}
		for j, ipv6 := range iface.IPv6.Addr {
			keyPrefix := azurePrefix + "network/interface/" +
				fmt.Sprintf("%d/ipv6/ipaddress/%d/", i, j)
			if ipv6.PrivateIP != "" {
				result[keyPrefix+"privateipaddress"] = ipv6.PrivateIP
				ipAddrs[instance.KeyPrivateIPV6s] = append(ipAddrs[instance.KeyPrivateIPV6s],
					ipv6.PrivateIP)
			}
			if ipv6.PublicIP != "" {
				result[keyPrefix+"publicipaddress"] = ipv6.PublicIP
				ipAddrs[instance.KeyPublicIPV6s] = append(ipAddrs[instance.KeyPublicIPV6s],
					ipv6.PublicIP)
			}
		}
		for j, netv6 := range iface.IPv6.Subnet {
			keyPrefix := azurePrefix + "network/interface/" +
				fmt.Sprintf("%d/ipv6/subnet/%d/", i, j)
			if netv6.Address != "" {
				result[keyPrefix+"address"] = netv6.Address
			}
			if netv6.Prefix != "" {
				result[keyPrefix+"prefix"] = netv6.Prefix
			}
		}
	}

	instance.AddToResult(ipAddrs, result)
}
