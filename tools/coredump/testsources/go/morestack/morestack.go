package main

import "fmt"

func fib(n int) int {
	if n <= 1 {
		return n
	}
	return fib(n-1) + fib(n-2)
}

//go:noinline
func deepfib(depth, n int) int {
	var buf [256]byte
	buf[0] = byte(depth)
	if depth > 0 {
		return int(buf[0]) + deepfib(depth-1, n)
	}
	return fib(n)
}

func main() {
	for {
		fmt.Printf("%d\n", deepfib(100, 40))
	}
}
