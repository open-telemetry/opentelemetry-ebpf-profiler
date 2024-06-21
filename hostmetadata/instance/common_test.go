/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package instance

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEnumerate(t *testing.T) {
	r := Enumerate("")
	assert.Equal(t, []string{}, r)

	r = Enumerate("\n")
	assert.Equal(t, []string{}, r)

	r = Enumerate("\n\n")
	assert.Equal(t, []string{}, r)

	r = Enumerate("\nhello\n")
	assert.Equal(t, []string{"hello"}, r)

	r = Enumerate("\nhello/\n")
	assert.Equal(t, []string{"hello"}, r)

	r = Enumerate("hi\nhello/\n")
	assert.Equal(t, []string{"hi", "hello"}, r)

	r = Enumerate("hi\nhello/\n\nbye")
	assert.Equal(t, []string{"hi", "hello", "bye"}, r)

	r = Enumerate("\nbye")
	assert.Equal(t, []string{"bye"}, r)

	r = Enumerate("hello/\n")
	assert.Equal(t, []string{"hello"}, r)

	r = Enumerate("hello/")
	assert.Equal(t, []string{"hello"}, r)

	r = Enumerate("\nhello/ \n")
	assert.Equal(t, []string{"hello"}, r)

	r = Enumerate("hi\n \nbye")
	assert.Equal(t, []string{"hi", "bye"}, r)
}
