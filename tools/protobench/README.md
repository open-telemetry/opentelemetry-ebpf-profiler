## Introduction

The idea is to record the wire messages of the profiling agent and see how well they compress using different
compressors and what the CPU impact is.

To record the wire messages, you need to run the profiling agent with the `-reporter-save-outputs-to` flag.
This will write the wire messages into the given directory. The directory will be created if it does not exist.

You can then use the `protobench` tool to compress the wire messages and see how well they compress and how much
CPU time it takes to compress them.

### Recording wire messages

Make sure you have a receiving endpoint, e.g. `devfiler` listening on localhost:11000.
Now run the profiling agent with the `-reporter-save-outputs-to` flag:
```shell
sudo ./opentelemetry-ebpf-profiler -reporter-save-outputs-to=/tmp/protobuf -collection-agent=127.0.0.1:11000 -disable-tls
```
The wire messages are written to `protobuf/`, one file per message.

### Benchmark compression of wire messages

In reality, the previously recorded wire messages are sent compressed over the network.
Compression efficiency and CPU usage are important factors to consider when choosing a compression algorithm.

The `protobench` tool helps to compare compression algorithms and their performance:
- for realistic results, wire messages are compressed one-by-one
- different compressors with different compression levels are used
- the compression ratio and CPU usage are measured
- the results are written as a bar chart or a CSV file

To compress the wire messages and generate a bar chart, run the `protobench` tool with an output file ending in `.png`:
```shell
cd tools/protobench
go run ./... -bench-proto-dir=/tmp/protobuf -output-file=results.png
```
If you don't see any errors, the tool will generate a PNG file with a bar chart showing the compression ratio and
CPU usage for each compressor/level.
The extension `.csv` can be used to generate a CSV file with the raw data instead of a PNG file.
No `-output-file` flag will display the results in the terminal.

Of course, you can also use the `protobench` tool to compare compression of any other files.

### Reproducible reporter outputs

The profiling agent supports recording and replaying reporter inputs with the `-reporter-record-inputs-to` and
`-reporter-replay-inputs-from` flags.

Replaying in combination with `-reporter-save-outputs-to` generates a (nearly) reproducible set of wire messages,
which be easily compared with the `protobench` tool. This can be useful for comparing different implementations of
the reporter or the wire protocol.

Generated inputs can be shared for CI, benchmarking, development, testing or debugging purposes.

### Example PNG output

![Example output](example.png)
