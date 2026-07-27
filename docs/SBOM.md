# wolfHSM SBOM Generation

wolfHSM can emit a Software Bill of Materials (SBOM) in **CycloneDX 1.6** and
**SPDX 2.3** JSON. An SBOM is one of the software-transparency artifacts useful
towards EU Cyber Resilience Act (CRA) obligations; it does not by itself make a
product CRA compliant.

## One engine

There is a single SBOM engine. The Make front end feeds it the source list and
the build configuration, then calls the vendored wolfGlass driver:

```
make sbom  ─►  tools/sbom/sbom-driver  ─►  tools/sbom/gen-sbom  ─►  *.cdx.json + *.spdx.json
```

| File | Role |
| --- | --- |
| `tools/sbom/sbom-driver` | Vendored wolfGlass driver (srcs + config → gen-sbom). |
| `tools/sbom/gen-sbom` | Vendored SBOM generator. |
| `tools/sbom/build/sbom.mk` | Shared plain-Make fragment. |
| `tools/sbom/validate_sbom.py` | Structural sanity check used by CI. |

## Prerequisites

* `python3`
* A host C compiler (`HOSTCC`, default `cc`)
* The vendored wolfGlass SBOM set under `tools/sbom/`
* `WOLFHSM_CFG_DIR` — **required**. Point it at the directory that holds the
  `wolfhsm_cfg.h` and `user_settings.h` your build uses. There is no default;
  `test/config` is a test harness config, not a release configuration.
* `WOLFSSL_DIR` — path to a wolfssl source tree used on the include path
  (default `../wolfssl`)

## Generate the core SBOM

```sh
make sbom WOLFSSL_DIR=../wolfssl WOLFHSM_CFG_DIR=/path/to/your/config
```

Outputs: `wolfhsm-<version>.cdx.json` and `wolfhsm-<version>.spdx.json`.

The Make target first runs `$(HOSTCC) -dM -E ... -include wolfhsm/wh_settings.h`
and feeds that dump to the driver as `--options-h` (`SBOM_OPTIONS_H`). Do
**not** use `SBOM_CFLAGS` for this product: the driver's `--cflags` path keeps
only `-D` tokens and drops `-I` / `-include`, which yields an empty config
record (two raw defines) instead of the real `WOLFHSM_CFG_*` / wolfSSL option
set.

Version is parsed from `ChangeLog.md` (for example `# wolfHSM Release v1.4.0`).
There is no product release version macro in the public headers today
(`WOLFHSM_CFG_INFOVERSION` is a protocol info string). Relying on ChangeLog
parsing is a known fragility to replace with a header macro later.

Useful overrides: `HOSTCC`, `SBOM_GEN`, `CRA_PYTHON`, `SBOM_DEP_WOLFSSL=no`
(for a `WOLFHSM_CFG_NO_CRYPTO` build). With `SBOM_DEP_WOLFSSL=yes` (default),
`sbom.mk` reads `$(WOLFSSL_DIR)/wolfssl/version.h` for the dependency version.

Validate locally (also guards empty captures and missing dep versions):

```sh
python3 tools/sbom/validate_sbom.py --name-prefix wolfhsm \
    --min-properties 50 --require-dep-version wolfssl \
    wolfhsm-*.cdx.json wolfhsm-*.spdx.json
```

## Coverage

| Target | Status | How | Notes |
| --- | --- | --- | --- |
| Core library (`src/*.c`) | Covered | `make sbom` | Config via `WOLFHSM_CFG_DIR` + `wh_settings.h` |
| `examples/posix/wh_posix_server` | **Not yet** | follow-up | Needs its own `sbom` target in that Makefile |
| `examples/posix/wh_posix_client` | **Not yet** | follow-up | Needs its own `sbom` target in that Makefile |
| `tools/whnvmtool` | **Not yet** | follow-up | Needs its own `sbom` target in that Makefile |
| `port/posix` (HAL sources alone) | **Not yet** | follow-up | May be folded into posix example targets |
| `port/infineon/tc3xx` | Out of scope | — | Restricted vendor stub; build files not public |
| `port/renesas/rh850f1km` | Out of scope | — | Restricted vendor stub; build files not public |
| `port/stmicro/spc58nn` | Out of scope | — | Restricted vendor stub; build files not public |
| `port/stmicro/SR6` | Out of scope | — | Restricted vendor stub; build files not public |
| `port/microchip/pic32cz` | Out of scope | — | Restricted vendor stub; build files not public |
| `port/ti/tda4vh` | Out of scope | — | Restricted vendor stub; build files not public |

Restricted ports: ask port owners whether private IDE/build tooling should get
out-of-tree SBOM support. Do not infer from the public stubs. Draft issue text
for the three Makefile follow-ups and the port-owner question lives in
[SBOM-FOLLOWUPS.md](SBOM-FOLLOWUPS.md) (not filed yet).

wolfHSM has no CMake, autotools, or public IAR/compdb front end in this tree.
Do not invent a CMake SBOM path for parity with other products.

## CI

`.github/workflows/test-sbom.yml` runs the core canary: `make sbom` against
`test/config`, validates both documents with `--min-properties 50` and
`--require-dep-version wolfssl` (so an empty `--cflags` capture cannot pass),
and checks toolchain neutrality (`HOSTCC=gcc` vs `HOSTCC=clang` with a fixed
`SOURCE_DATE_EPOCH`).

A coverage cell is only ✅ when (a) the target runs locally and (b) CI is green
for it. Do not mark ✅ on “should work” alone.

## Further reading

* [wolfssl/doc/CRA.md](https://github.com/wolfSSL/wolfssl/blob/master/doc/CRA.md)
* Vendored toolkit pin: `tools/sbom/VERSION` and `tools/sbom/.wolfglass-rev`
