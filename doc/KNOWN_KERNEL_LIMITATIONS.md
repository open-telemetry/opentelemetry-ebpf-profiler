Known limitations
=================
The Linux kernel is constantly evolving and so is eBPF. To be able to load our eBPF code with older kernel versions we have to write code to avoid some limitations. This file documents the restrictions we ran into while writing the code.

Number of tracepoints
---------------------
Affects kernel < 4.15.

There was a limit of 1 eBPF program per tracepoint/kprobe.
This limit no longer holds and was removed with commit [e87c6bc3852b981e71c757be20771546ce9f76f3](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e87c6bc3852b981e71c757be20771546ce9f76f3).


Kernel version check
--------------------
Affects kernel < 5.0.

As part of the verification of eBPF programs, the `kern_version` attribute was checked and it needed to match with the currently running kernel version.
This check was removed with commit [6c4fc209fcf9d27efbaa48368773e4d2bfbd59aa](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6c4fc209fcf9d27efbaa48368773e4d2bfbd59aa).


eBPF instruction limit
----------------------
Affects kernel < 5.2.

The number of eBPF instructions per program was limited to 4096 instructions.
This limit was raised to 1 million eBPF instructions with commit [c04c0d2b968ac45d6ef020316808ef6c82325a82](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c04c0d2b968ac45d6ef020316808ef6c82325a82).


eBPF inner arrays (map-in-map) must be of same size
---------------------------------------------------
Affects kernel < 5.10.

This restriction was removed with commit[4a8f87e60f6db40e640f1db555d063b2c4dea5f1](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=4a8f87e60f6db40e640f1db555d063b2c4dea5f1).
