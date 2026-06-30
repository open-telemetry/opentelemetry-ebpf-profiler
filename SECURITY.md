# Security Policy

Please first refer to the [OpenTelemetry org-wide security
policy](https://github.com/open-telemetry/.github/blob/main/SECURITY.md)

## Security Model

As stated in the OpenTelemetry org-wide security policy, the OpenTelemetry
project does not consider the following to be security vulnerabilities:

- a denial of service attack by properly authenticated clients
- availability-related attack to endpoints by properly authenticated clients

Currently, the ebpf-profiler project considers the containers and executables
which are being profiled to be "properly authenticated clients". So this
project **does not consider the following to be security vulnerabilities**:

- a denial of service attack by a crafted executable in the profiled process
- a denial of service attack by a crafted library mimicking a supported
  high-level language and providing malformed introspection data
- excessive resource usage by crafted library mimicking a supported
  high-level language and providing malformed introspection data

The above issues are bugs. If possible submit a normal PR fixing the issue,
or create a normal GitHub issue about the matter.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

In order for the vulnerability reports to reach maintainers as soon as possible,
the preferred way is to use the `Report a vulnerability` button on the `Security`
tab in the respective GitHub repository. It creates a private communication channel
between the reporter and the maintainers.
