# Container syscall profile provenance

`moby-seccomp.json` is an **unmodified** copy of Moby v28.1.1's
[`profiles/seccomp/default.json`](https://github.com/moby/moby/blob/v28.1.1/profiles/seccomp/default.json),
retrieved from that tagged upstream release. SHA-256:

```text
9c1025c88ccaa517b648da571961838744ea2137f176bfe6a48b21294cae9c76
```

It uses `SCMP_ACT_ERRNO` as the default action and allows enumerated system calls
subject to architecture and capability conditions. The accompanying
`LICENSE.moby` and `NOTICE.moby` are copied from the same Moby release. The
upstream profile is Apache-2.0 licensed; the repository's MIT license does not
replace those upstream terms.

Compose applies this explicit profile because a Docker daemon can be configured
with an unconfined default. The containment check requires the running workers
to report seccomp filter mode (`Seccomp: 2`); it fails instead of silently
accepting an unconfined daemon or unsupported platform. Docker administrator
access remains trusted and can override these protections.
