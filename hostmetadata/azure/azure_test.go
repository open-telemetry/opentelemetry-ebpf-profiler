/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package azure

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nolint:lll
const fakeAzureAnswer = `{
  "compute": {
    "azEnvironment": "AzurePublicCloud",
    "customData": "",
    "isHostCompatibilityLayerVm": "false",
    "licenseType": "",
    "location": "westeurope",
    "name": "bar-test",
    "offer": "UbuntuServer",
    "osProfile": {
      "adminUsername": "azureuser",
      "computerName": "bar-test"
    },
    "osType": "Linux",
    "placementGroupId": "",
    "plan": {
      "name": "",
      "product": "",
      "publisher": ""
    },
    "platformFaultDomain": "0",
    "platformUpdateDomain": "0",
    "provider": "Microsoft.Compute",
    "publicKeys": [
      {
        "keyData": "ssh-rsa AAAAB3NzaC1yhMLIRQxCVYTdesFRQ+0= generated-by-azure\r\n",
        "path": "/home/azureuser/.ssh/authorized_keys"
      }
    ],
    "publisher": "Canonical",
    "resourceGroupName": "cloud-shell-storage-westeurope",
    "resourceId": "/subscriptions/ebdce8e8-f00-e091c79f86/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.Compute/virtualMachines/bar-test",
    "securityProfile": {
      "secureBootEnabled": "false",
      "virtualTpmEnabled": "false"
    },
    "sku": "18.04-LTS",
    "storageProfile": {
      "dataDisks": [],
      "imageReference": {
        "id": "",
        "offer": "UbuntuServer",
        "publisher": "Canonical",
        "sku": "18.04-LTS",
        "version": "latest"
      },
      "osDisk": {
        "caching": "ReadWrite",
        "createOption": "FromImage",
        "diffDiskSettings": {
          "option": ""
        },
        "diskSizeGB": "30",
        "encryptionSettings": {
          "enabled": "false"
        },
        "image": {
          "uri": ""
        },
        "managedDisk": {
          "id": "/subscriptions/ebdce8e8-f00-e091c79f86/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.Compute/disks/bar-test_OsDisk_1_c0ffeec7c6bd7",
          "storageAccountType": "Standard_LRS"
        },
        "name": "bar-test_OsDisk_1_c0ffeec7c6bd7",
        "osType": "Linux",
        "vhd": {
          "uri": ""
        },
        "writeAcceleratorEnabled": "false"
      }
    },
    "subscriptionId": "ebdce8e8-f00-e091c79f86",
    "tags": "baz:bash;foo:bar",
    "tagsList": [],
    "version": "18.04.202103250",
    "vmId": "1576434a-f66c-4ffe-abba-44b6a8f8",
    "vmScaleSetName": "",
    "vmSize": "Standard_DS1_v2",
    "zone": "testzone"
  },
  "network": {
    "interface": [
      {
        "ipv4": {
          "ipAddress": [
            {
              "privateIpAddress": "10.0.0.4",
              "publicIpAddress": "20.73.42.73"
            },
            {
              "privateIpAddress": "10.0.0.5",
              "publicIpAddress": "20.73.42.74"
            }
          ],
          "subnet": [
            {
              "address": "10.0.0.0",
              "prefix": "24"
            }
          ]
        },
        "ipv6": {
          "ipAddress": []
        },
        "macAddress": "0022488250E5"
      }
    ]
  }
}`

var expectedResult = map[string]string{
	"cloud:provider":               "azure",
	"cloud:region":                 "westeurope",
	"host:type":                    "Standard_DS1_v2",
	"azure:compute/environment":    "AzurePublicCloud",
	"azure:compute/location":       "westeurope",
	"azure:compute/name":           "bar-test",
	"azure:compute/offer":          "UbuntuServer",
	"azure:compute/ostype":         "Linux",
	"azure:compute/publisher":      "Canonical",
	"azure:compute/sku":            "18.04-LTS",
	"azure:compute/subscriptionid": "ebdce8e8-f00-e091c79f86",
	"azure:compute/version":        "18.04.202103250",
	"azure:compute/vmid":           "1576434a-f66c-4ffe-abba-44b6a8f8",
	"azure:compute/vmsize":         "Standard_DS1_v2",
	"azure:compute/tags":           "baz:bash;foo:bar",
	"azure:compute/zone":           "testzone",
	"azure:network/interface/0/ipv4/ipaddress/0/privateipaddress": "10.0.0.4",
	"azure:network/interface/0/ipv4/ipaddress/0/publicipaddress":  "20.73.42.73",
	"azure:network/interface/0/ipv4/ipaddress/1/privateipaddress": "10.0.0.5",
	"azure:network/interface/0/ipv4/ipaddress/1/publicipaddress":  "20.73.42.74",
	"azure:network/interface/0/ipv4/subnet/0/address":             "10.0.0.0",
	"azure:network/interface/0/ipv4/subnet/0/prefix":              "24",
	"azure:network/interface/0/macaddress":                        "0022488250E5",
	"instance:public-ipv4s":                                       "20.73.42.73,20.73.42.74",
	"instance:private-ipv4s":                                      "10.0.0.4,10.0.0.5",
}

func TestPopulateResult(t *testing.T) {
	var imds IMDS
	result := make(map[string]string)

	azure := strings.NewReader(fakeAzureAnswer)

	err := json.NewDecoder(azure).Decode(&imds)
	require.NoError(t, err)

	populateResult(result, &imds)
	assert.Equal(t, expectedResult, result)
}
