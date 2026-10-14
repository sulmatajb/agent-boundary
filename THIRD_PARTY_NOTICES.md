# Third-party notices

Agent Boundary's original code and documentation are licensed under the root
[MIT license](LICENSE). The following vendored file retains its upstream terms.

| File | Upstream source | License |
| --- | --- | --- |
| `security/moby-seccomp.json` | Moby v28.1.1, `profiles/seccomp/default.json` | Apache-2.0 |

The syscall profile is an **unmodified** copy. Its source URL and SHA-256 digest
are recorded in [the provenance note](security/README.md). The upstream
[Apache-2.0 license](security/LICENSE.moby) and
[NOTICE](security/NOTICE.moby) accompany it; preserve both when redistributing
the profile. Agent Boundary's MIT license does not replace those terms.

Package metadata uses `MIT AND Apache-2.0` to identify the licenses represented
in the source distribution. This does not relicense the project's original
code. The wheel retains the attribution and license texts as well.

Python, Docker, and the Codex CLI are separately installed tools and are not
vendored in the Python package. The Docker base image is referenced by digest;
its software retains its own licenses. This notice does not grant rights to
those separately obtained products or describe their service terms.
