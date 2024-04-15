/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import "fmt"

//go:noinline
func leaf() {}

//go:noinline
func hello() {
	fmt.Println("hello world!")
	hello1()
}

//go:noinline
func hello1() {
	hello2()
	fmt.Println("hello world!")
}

//go:noinline
func hello2() {
	fmt.Println("hello world!")
	x := make([]uint32, 3345)
	hello3(x)
}

//go:noinline
func hello3(x []uint32) {
	hello4()
	fmt.Printf("hello world! %x", x[2234])
}

//go:noinline
func hello4() {
	hello5()
	fmt.Println("hello world!")
}

//go:noinline
func hello5() {
	fmt.Println("hello world!")
	leaf()
}

func main() {
	hello()
}
