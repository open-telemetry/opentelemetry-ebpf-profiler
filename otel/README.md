The collector code is just meant as an example.
The receiver code needs to use the OTEL profiling API, once that is available.
Technically, the receiver and collector code can both live in separate repositories.


To get the `ocb` tool (OTEL collector builder, amend version):
```
curl --proto '=https' --tlsv1.2 -fL -o ocb https://github.com/open-telemetry/opentelemetry-collector/releases/download/cmd%2Fbuilder%2Fv0.106.0/ocb_0.106.0_linux_amd64
chmod a+x ocb
```

To build a static version of the collector with glibc
```
./ocb --skip-strict-versioning --verbose --config builder-config.yaml
```

To build a static version of the collector with muslc (on x86/amd64)
```
CC=x86_64-linux-musl-gcc \
CGO_ENABLED=1 \
./ocb --skip-strict-versioning --verbose --config builder-config.yaml \
  --ldflags="-linkmode external -extldflags=-static"
```

Run the collector (start devfiler first)
```
sudo collector/profiling-collector --config collector/config.yaml
```
