# emp-compat — vendored emp-tool headers the migration depends on

The fullport migration's `compat/primus_compat.h` + otls backend/cipher compile against
a few emp-tool headers that are **NOT** produced by building the current upstream
emp-toolkit source (`perf-check/emp-{tool,ot,zk}`). They lived only in a stale
`install-up/include` build artifact, so a clean from-source build was not reproducible
(see migration/FULLPORT_LOG.md "Phase 5 VPS — 可复现性缺口").

This dir vendors exactly those headers so the build needs only:
  - upstream emp **headers from source** (the modern `emp-tool/runtime/...` layout), and
  - the linked `libemp-{tool,ot,zk}.a`,
with **no patching of the external emp repos**. Add `-Iemp-compat/include` to the build.

## The 5 headers (determined by `g++ -M` over every otls + pado TU)

REAL CONTENT (genuinely needed — no upstream counterpart):
  - `emp-tool/execution/backend.h`    — the migration's unified `emp::Backend` abstraction
                                         (global `extern Backend* backend`; GC+ZK dispatch).
  - `emp-tool/circuits/circuit_file.h` — the fork-style `BristolFormat` the cipher layer uses
                                         (the modern emp-tool reorganized circuits; this exact
                                         header is gone upstream).

PATH PLACEHOLDERS (content is **superseded at compile time** by the upstream
`emp-tool/runtime/...` version — same include guard, included first via emp-tool.h, so
these bodies are skipped; they exist ONLY so the flat `#include "emp-tool/core/block.h"`
etc. issued by backend.h/circuit_file.h resolve to a file instead of fatal not-found):
  - `emp-tool/core/block.h`        (guard EMP_UTIL_BLOCK_H__  → upstream runtime/core/block.h wins)
  - `emp-tool/core/constants.h`    (guard EMP_CONFIG_H__      → upstream runtime/core/constants.h wins)
  - `emp-tool/io/io_channel.h`     (guard EMP_IO_CHANNEL_H__  → upstream runtime/io/io_channel.h wins)
  - `emp-tool/io/net_io_channel.h` (test-harness only — otls tests use NetIO; body skipped,
                                    so its flat `#include "emp-tool/io/tcp_socket.h"` is never
                                    reached, tcp_socket comes from upstream runtime/io/. The
                                    pado SDK itself uses PadoIO/WebSocketIO, not NetIO.)

Both REAL-content headers have NO upstream counterpart, so their bodies ARE compiled.
The 4 placeholders rely on the keystone force-including emp-tool.h FIRST (so the upstream
runtime version sets the shared guard before the flat copy is reached). That ordering is
guaranteed by the build's `-include compat/primus_compat.h`.

## Verified
Clean-room on x86_64/Linux/g++ (VPS): fresh from-source emp (no stale install-up) +
this emp-compat → otls builds, prove_aes accept/tamper-reject, protocol gc/zk AND =
1703395/1726528 (gate-identical to the validated build). See FULLPORT_LOG.md.
