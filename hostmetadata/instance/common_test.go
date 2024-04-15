/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package instance

import (
	"reflect"
	"testing"
)

func TestEnumerate(t *testing.T) {
	r := Enumerate("")
	if !reflect.DeepEqual([]string{}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("\n")
	if !reflect.DeepEqual([]string{}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("\n\n")
	if !reflect.DeepEqual([]string{}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("\nhello\n")
	if !reflect.DeepEqual([]string{"hello"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("\nhello/\n")
	if !reflect.DeepEqual([]string{"hello"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("hi\nhello/\n")
	if !reflect.DeepEqual([]string{"hi", "hello"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("hi\nhello/\n\nbye")
	if !reflect.DeepEqual([]string{"hi", "hello", "bye"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("\nbye")
	if !reflect.DeepEqual([]string{"bye"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("hello/\n")
	if !reflect.DeepEqual([]string{"hello"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("hello/")
	if !reflect.DeepEqual([]string{"hello"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("\nhello/ \n")
	if !reflect.DeepEqual([]string{"hello"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}

	r = Enumerate("hi\n \nbye")
	if !reflect.DeepEqual([]string{"hi", "bye"}, r) {
		t.Fatalf("unexpected result: %#v", r)
	}
}
