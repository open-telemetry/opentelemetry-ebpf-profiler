Amalgamated Zydis
=================

This directory contains the [amalgamated distribution] of Zydis. We ship
the library as part of this repository to:

- allow pulling in this repository as a library via the Go module system
- automatically have it be compiled according to `GOOS` and `GOARCH` settings

Current library version shipped in this directory: **v4.1.0**

[amalgamated distribution]: https://github.com/zyantific/zydis?tab=readme-ov-file#amalgamated-distribution

## Updating the library

- Look for the [latest Zydis release](https://github.com/zyantific/zydis/releases)
- Download and extract the `zydis-amalgamated.tar.gz` release artifact
- Replace `Zydis.h` and `Zydis.c` in this directory with the newly extracted variants
