/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package modulestore

import (
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/service/s3"
)

// getS3ObjectList gets all matching objects in an S3 bucket.
func getS3ObjectList(client *s3.S3, bucket, prefix string, itemLimit int) ([]*s3.Object, error) {
	var objects []*s3.Object
	var contToken *string
	var batchSize int64 = s3ResultsPerPage

	for {
		resp, err := client.ListObjectsV2(&s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			MaxKeys:           &batchSize,
			ContinuationToken: contToken,
		})

		if err != nil {
			return nil, fmt.Errorf("s3 request failed: %w", err)
		}

		objects = append(objects, resp.Contents...)

		if int64(len(resp.Contents)) != batchSize {
			break
		}
		if len(resp.Contents) > itemLimit {
			return nil, errors.New("too many matching items in bucket")
		}

		contToken = resp.ContinuationToken
	}

	return objects, nil
}
