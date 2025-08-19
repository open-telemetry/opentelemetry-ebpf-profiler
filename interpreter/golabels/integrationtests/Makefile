.PHONY: pprof pprof_1_23 pprof_1_24 pprof_1_24_cgo clean

pprof: pprof_1_23 pprof_1_24 pprof_1_24_cgo 

pprof_1_23:
	CGO_ENABLED=0 GOTOOLCHAIN=go1.23.7 go test -C ./pprof -c -trimpath -tags nocgo,integration -o ./../$@

pprof_1_24:
	CGO_ENABLED=0 GOTOOLCHAIN=go1.24.6 go test -C ./pprof -c -trimpath -tags nocgo,integration  -o ./../$@

pprof_1_24_cgo:
	CGO_ENABLED=1 GOTOOLCHAIN=go1.24.6 go test -C ./pprof -c -ldflags '-extldflags "-static"' -trimpath -tags withcgo,integration  -o ./../$@

clean:
	rm pprof_1_*