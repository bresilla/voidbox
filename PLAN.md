# Quality Hardening Plan (Post-Rename)

This plan tracks implementation-quality gaps found during the deep audit of `bin/` + `lib/`.

## Commit Discipline (Mandatory)

- After each task below is implemented and validated, create a dedicated git commit.
- Keep commits focused to one task (or one tightly related subtask group).
- Run relevant validation before each commit (`zig build test`, `make build`, and targeted runtime checks).
- Push after each commit.

## Priority Queue

### P0 Critical

1. Implement real `--lock-file` locking semantics
   - Current issue: lock file is opened but never actually locked.
   - Files: `lib/session.zig`
   - Target behavior:
     - acquire an exclusive lock for session lifetime;
     - fail clearly (or block, per chosen policy) when lock is held;
     - release lock on teardown.
   - Validation:
     - concurrent launch test shows one holder only;
     - lock released after process exits.
   - Commit: required immediately after validation.

2. Eliminate cross-run resource collisions by introducing unique runtime instance IDs
   - Current issue: default/duplicate names can collide in cgroup/net resources.
   - Files: `bin/vb.zig`, `lib/container.zig`, `lib/cgroup.zig`, `lib/network.zig`, any path/key builders.
   - Target behavior:
     - separate human-facing name from unique internal runtime ID;
     - resource paths/names use internal ID;
     - teardown removes only owned resources.
   - Validation:
     - run multiple concurrent instances; no resource path/name collisions.
   - Commit: required immediately after validation.

### P1 High

3. Harden parent spawn resource lifecycle (fd/stack cleanup)
   - Current issue: incomplete parent cleanup and leak-prone lifecycle around clone/pipe.
   - Files: `lib/container.zig`
   - Target behavior:
     - deterministic close of both pipe ends in all paths;
     - no stack allocation leaks;
     - robust `errdefer`/`defer` for success/failure symmetry.
   - Validation:
     - stress launch loop without fd growth;
     - tests + build pass.
   - Commit: required immediately after validation.

4. Fix rtnetlink socket creation and parsing safety
   - Current issue: unsafe syscall/fd assumptions and weak message/attr bounds checks.
   - Files: `lib/rtnetlink/rtnetlink.zig`, `lib/rtnetlink/link/get.zig`, `lib/rtnetlink/route/get.zig`, related parsers.
   - Target behavior:
     - safe socket init path with explicit error handling;
     - strict bounds checks before reading headers/attrs;
     - no infinite/invalid attr loops on malformed messages.
   - Validation:
     - tests pass;
     - parser fuzz-like malformed input tests (unit-level) where practical.
   - Commit: required immediately after validation.

5. Delay `setup_finished` event until child setup is actually complete
   - Current issue: event emitted too early.
   - Files: `lib/session.zig`, `lib/container.zig`, status signaling path.
   - Target behavior:
     - explicit child-to-parent readiness signal after setup phase completes;
     - event ordering reflects real lifecycle.
   - Validation:
     - event-sequence test covers spawned -> setup_finished -> exited ordering.
   - Commit: required immediately after validation.

6. Fix broadcast/endian correctness in address route helper
   - Current issue: broadcast computation endianness risk.
   - Files: `lib/rtnetlink/address/add.zig`
   - Target behavior:
     - broadcast derived with correct network byte-order math.
   - Validation:
     - deterministic tests for representative prefixes.
   - Commit: required immediately after validation.

### P2 Medium

7. Add parser-owned memory cleanup for allocated helper strings/slices
   - Current issue: long-lived parser allocations can leak in runtime process.
   - Files: `bin/vb.zig` (`--args` expansion, `--bind-fd` generated strings, overlay keys, etc.)
   - Target behavior:
     - clear ownership model;
     - deinit/cleanup for parser-created allocations.
   - Validation:
     - unit tests with allocator leak checks where feasible.
   - Commit: required immediately after validation.

8. Add cleanup lifecycle for temporary fs artifacts
   - Current issue: temp files/dirs can accumulate.
   - Files: `lib/fs_actions.zig`
   - Target behavior:
     - track created temp paths;
     - cleanup on success and rollback paths.
   - Validation:
     - integration run leaves no new stale temp artifacts.
   - Commit: required immediately after validation.

9. Surface runtime init failures with structured errors/warnings
   - Current issue: important init failures are swallowed.
   - Files: `lib/runtime.zig`
   - Target behavior:
     - return typed errors or explicit warnings;
     - avoid silent degraded state.
   - Validation:
     - tests and explicit failure-mode checks.
   - Commit: required immediately after validation.

### P3 Low / Deferred Cleanup

10. Replace remaining placeholders with explicit support/unsupported behavior
   - Items include IP collision handling, partial IPv6 attrs, and no-op normalization hook.
   - Files: `lib/ip.zig`, `lib/rtnetlink/address/attrs.zig`, `lib/namespace_semantics.zig`.
   - Target behavior:
     - implement or fail explicitly with clear errors and docs.
   - Commit: required immediately after each sub-item validation.

## Execution Strategy

1. Complete all P0 tasks first, one commit each.
2. Proceed with P1 in listed order, one commit each.
3. Proceed with P2/P3 similarly.
4. After every 2-3 commits, run an extended regression matrix for user + sudo scenarios.

## Done Criteria

- No known critical/high issues remain in this plan.
- `zig build test` and `make build` pass after every task.
- Runtime regression matrix remains green after each batch.
- Commit history clearly reflects one validated fix per task.

## Progress Snapshot (2026-02-12)

### Completed Or Effectively Completed

- P0-1: lock-file locking semantics (`lib/session.zig`) with exclusivity and reacquire tests.
- P0-2: runtime instance-id pathing to reduce cross-run collisions.
- P1-4/P1-5/P1-6: rtnetlink parser/socket hardening, setup-finished ordering, and broadcast/endian correctness.
- P2-7/P2-8/P2-9: parser-owned allocation cleanup hardening, fs artifact cleanup lifecycle fixes, runtime warning surfacing.
- Addendum 11-16, 18-20: chroot path safety, error-path stability, parser bounds/alignment improvements, resource lifecycle and networking overhead/collision hardening.
- Regression 21-23: malformed parser tests, leak/repetition tests, and parallel stress matrix expansions.

### Remaining / Partial

- P1-3: parent spawn lifecycle hardening is mostly complete; keep adding focused fd-lifecycle failure-path checks.
- Addendum 17: PID1 behavior improved significantly, but not yet full init-grade semantics.
- Addendum 20 (IPv6): explicit unsupported handling is in place; full IPv6 route attribute support remains deferred.

## Deep Audit Addendum (2026-02-11)

This addendum captures additional findings from a full code audit focused on performance, memory/resource lifecycle, parser safety, and missing functionality.

### Build/Test Baseline

- `make build`: passes.
- `zig build test`: passes.

### New P0 Critical

11. Fix unsafe `chroot` path syscall argument handling
   - Current issue: `linux.chroot(@ptrCast(rootfs))` uses a non-sentinel slice pointer for a syscall interface that expects NUL-terminated path semantics.
   - Files: `lib/mounts.zig`.
   - Target behavior:
     - pass properly terminated path buffers to kernel-facing path syscalls;
     - remove undefined-behavior-prone pointer casts for filesystem paths.
   - Validation:
     - unit tests for path conversion helpers;
     - integration smoke launch in chroot path succeeds.
   - Commit: required immediately after validation.

12. Remove panic-prone `unreachable` paths in rtnetlink response handling
   - Current issue: parser paths can hit `unreachable` after netlink error ACK handling.
   - Files: `lib/rtnetlink/link/get.zig`, `lib/rtnetlink/route/get.zig`.
   - Target behavior:
     - return explicit typed errors instead of panicking;
     - preserve process stability on malformed or unexpected kernel responses.
   - Validation:
     - malformed response tests confirm graceful error returns.
   - Commit: required immediately after validation.

### New P1 High

13. Fix rtnetlink multipart/alignment iteration correctness
   - Current issue: route message iteration advances by raw header length and does not robustly handle multipart framing/alignment.
   - Files: `lib/rtnetlink/route/get.zig`, `lib/rtnetlink/link/get.zig`, `lib/rtnetlink/utils.zig`.
   - Target behavior:
     - iterate with proper netlink alignment semantics;
     - correctly stop at DONE and reject truncated/inconsistent lengths.
   - Validation:
     - unit tests for aligned and malformed message buffers;
     - route/link lookups stable under repeated calls.
   - Commit: required immediately after validation.

14. Close rtnetlink object/resource leaks in network lifecycle
   - Current issue: leaked `LinkMessage` objects and early-return paths that skip netlink socket deinit.
   - Files: `lib/network.zig`, `lib/rtnetlink/link/get.zig`, `lib/rtnetlink/link/link.zig`, `lib/rtnetlink/rtnetlink.zig`, address message ownership paths.
   - Target behavior:
     - every `linkGet`/address message allocation has clear ownership and deinit;
     - network teardown always deinitializes netlink socket even when link deletion fails.
   - Validation:
     - allocator-backed leak tests for repeated link/address operations;
     - teardown path test verifies no fd growth and deterministic deinit.
   - Commit: required immediately after validation.

15. Harden cgroup writes against partial I/O
   - Current issue: resource limit writes use `write` + assert instead of full write semantics.
   - Files: `lib/cgroup.zig`.
   - Target behavior:
     - use `writeAll` and propagate write failures cleanly.
   - Validation:
     - cgroup limit integration checks pass;
     - no debug-assert dependency for correctness.
   - Commit: required immediately after validation.

16. Promote runtime init degradation to structured surfaced state
   - Current issue: runtime initialization warnings are logged but not surfaced strongly enough to callers.
   - Files: `lib/runtime.zig`, `lib/session.zig`, public error/reporting path.
   - Target behavior:
     - explicit typed warning/error propagation path to caller;
     - avoid silent degraded operation when core runtime directories/controllers are unavailable.
   - Validation:
     - failure-mode tests for missing runtime dirs and cgroup controller writes.
   - Commit: required immediately after validation.

### New P2 Medium

17. Implement robust PID 1 behavior or explicitly constrain semantics
   - Current issue: PID 1 path is minimal and does not provide full init-style signal forwarding/reaping behavior.
   - Files: `lib/container.zig`.
   - Target behavior:
     - either implement init-like signal handling/zombie reaping semantics;
     - or fail/guard with explicit unsupported behavior and documentation.
   - Validation:
     - tests for signal forwarding and child reaping behavior in pid namespace mode.
   - Commit: required immediately after validation.

18. Reduce per-launch networking overhead
   - Current issue: repeated external `iptables` process invocations and repeated route/link discovery on each launch.
   - Files: `lib/network.zig`.
   - Target behavior:
     - minimize external process spawning;
     - cache or streamline gateway/interface discovery when safe.
   - Validation:
     - micro-benchmark repeated launch path;
     - functional parity for NAT setup.
   - Commit: required immediately after validation.

19. Add explicit collision strategy for container IPv4 assignment
   - Current issue: deterministic hash-based host octet mapping has no collision detection/avoidance.
   - Files: `lib/ip.zig`, `lib/network.zig`.
   - Target behavior:
     - detect already-assigned addresses and resolve collisions deterministically.
   - Validation:
     - deterministic tests covering forced-collision scenarios.
   - Commit: required immediately after validation.

20. Expand rtnetlink route attribute support and explicit unsupported responses
   - Current issue: partial route attribute parsing and IPv6 not supported in route attrs.
   - Files: `lib/rtnetlink/route/get.zig`, `lib/rtnetlink/route/attrs.zig`.
   - Target behavior:
     - parse required attrs with strict bounds checks;
     - for unsupported attrs/families, return explicit typed unsupported errors where needed.
   - Validation:
     - parser tests for IPv4 attrs and explicit unsupported IPv6 paths.
   - Commit: required immediately after validation.

### Regression/Test Expansion Requirements

21. Add malformed-netlink parser hardening tests
   - Files: `lib/rtnetlink/link/get.zig`, `lib/rtnetlink/route/get.zig`.
   - Coverage:
     - truncated headers;
     - invalid attr lengths;
     - malformed multipart termination.

22. Add leak-oriented repetition tests for rtnetlink/network paths
   - Files: rtnetlink and network modules.
   - Coverage:
     - repeated link/address get/add flows with allocator leak checks;
     - repeated network init/deinit cycles with fd stability checks.

23. Add concurrency/stress launch matrix
   - Files: integration test harness.
   - Coverage:
     - parallel container launches with network and cgroup enabled;
     - teardown race resilience and resource ownership isolation.

### Updated Execution Strategy

1. Complete original P0 items first if still open, then Deep Audit P0 (11-12), one commit each.
2. Complete P1 items (original and new 13-16) in order, one commit each.
3. Complete P2/P3 items (including 17-20), one commit each.
4. Execute regression expansion items (21-23) after parser/lifecycle hardening lands.
5. After every 2-3 commits, run `zig build test` and `make build`, plus targeted runtime checks.
