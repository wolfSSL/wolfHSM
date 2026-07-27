# SBOM follow-up issues (drafts)

These were prepared for `wolfSSL/wolfHSM` as Step 8 of the wolfGlass
migration. They were not filed automatically — create them when ready
(for example with `gh issue create --repo wolfSSL/wolfHSM`).

---

## 1. Add wolfGlass sbom target to examples/posix/wh_posix_server/Makefile

Follow-up from the wolfGlass SBOM migration (PR #414 lineage): add a
`sbom` Make target to `examples/posix/wh_posix_server/Makefile` using
the vendored `tools/sbom/build/sbom.mk` driver (same pattern as the
core root `Makefile`).

Core-only pass covers `src/*.c` via root `make sbom`. posix-server is
intentionally not marked ✅ until both (a) the target runs locally and
(b) CI covers it.

See `docs/SBOM.md` coverage table.

---

## 2. Add wolfGlass sbom target to examples/posix/wh_posix_client/Makefile

Same as (1) for `examples/posix/wh_posix_client/Makefile`.

---

## 3. Add wolfGlass sbom target to tools/whnvmtool/Makefile

Same as (1) for `tools/whnvmtool/Makefile`.

---

## 4. Confirm whether restricted vendor ports need out-of-tree SBOM support

Ask port owners directly (do not infer from public stubs):

- `port/infineon/tc3xx`
- `port/renesas/rh850f1km`
- `port/stmicro/spc58nn`
- `port/stmicro/SR6`
- `port/microchip/pic32cz`
- `port/ti/tda4vh`

Build files are not public. If a private port has a real build, it may
still need an out-of-tree wolfGlass front end. Owners: reply yes/no +
front end (Make / CMake / IAR / compdb / other) per port.
