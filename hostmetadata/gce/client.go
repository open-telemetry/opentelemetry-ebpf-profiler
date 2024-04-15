/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package gce

import gcemetadata "cloud.google.com/go/compute/metadata"

// gceMetadataClient is a type that implements the gceMetadataIface.
// Its purpose is to allow unit-testing of the metadata collection logic.
type gceMetadataClient struct {
}

// gceMetadataIface is an interface for the GCE metadata client
type gceMetadataIface interface {
	Get(p string) (string, error)
	InstanceTags() ([]string, error)
	OnGCE() bool
}

// Get forwards to gcemetadata.Get
func (*gceMetadataClient) Get(p string) (string, error) {
	return gcemetadata.Get(p)
}

// InstanceTags forwards to gcemetadata.InstanceTags
func (*gceMetadataClient) InstanceTags() ([]string, error) {
	return gcemetadata.InstanceTags()
}

// OnGCE forwards to gcemetadata.OnGCE
func (*gceMetadataClient) OnGCE() bool {
	return gcemetadata.OnGCE()
}
