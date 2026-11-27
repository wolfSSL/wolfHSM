# wolfHSM SBOM

Each public POSIX build writes a CycloneDX 1.6 file and an SPDX 2.3 file.

The generator is the vendored copy in `tools/sbom`. The pin is `tools/sbom/.wolfssl-compliance-tooling-rev`. Do not edit the files in `tools/sbom`.

## Build

From the repository root:

```
make sbom
```

This command writes the library SBOM and the test-program SBOM in the `test` directory.

You can run the same targets in one directory:

```
make -C test sbom
make -C test sbom-app
```

These directories have the same pair of targets:

- `benchmark`
- `examples/posix/wh_posix_server`
- `examples/posix/wh_posix_client`
- `test-refactor/posix`
- `tools/whnvmtool`

Set `WOLFSSL_DIR` to a wolfSSL tree. The default POSIX build includes wolfSSL headers. `NOCRYPTO=1` records no wolfSSL dependency. That build does not need the wolfSSL tree.

```
make -C test sbom NOCRYPTO=1
```

## Contents

The library SBOM lists `src/*.c` and `port/posix/*.c`. It does not hash the static archive. That archive also contains wolfSSL objects.

The program SBOM lists the C files of that program. It omits the wolfHSM library, the POSIX port, and wolfSSL.

The settings header is `wolfhsm/wh_settings.h`. The record keeps macros that start with `WOLFHSM_`.

`tools/whnvmtool` has no `WOLFHSM_CFG` define. Its SBOM records the `-D` flags in that Makefile.

The package version comes from the `wolfHSM Release` line in `ChangeLog.md`.

The license id is `GPL-3.0-or-later`.

## Ports

The directories in the build list above have a public Makefile and an SBOM target.

These vendor ports have no public build file, so they have no SBOM target:

- `port/infineon/tc3xx`
- `port/renesas/rh850f1km`
- `port/stmicro/SR6`
- `port/stmicro/spc58nn`
- `port/microchip/pic32cz`
- `port/ti/tda4vh`

`port/armv8m-tz`, `port/stmicro/stm32h5-tz`, and `port/skeleton` also have no Makefile.

## Check

Install the `spdx-tools` Python package. Then run:

```
python3 tools/sbom/validate_sbom.py --name-prefix wolfhsm FILE...
```
