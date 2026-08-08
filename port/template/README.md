# Template Port

This directory provides a starting point for porting wolfHSM to a new platform.
Each file contains stub implementations of the required interfaces with
documentation explaining what each function should do.

## Getting Started

1. Copy this directory to `port/<your_platform>/`.
2. Implement the transport layer for your platform (or use an existing one).
3. Fill in the `wh_Port_*` function stubs in `client/wh_client_port.c` and
   `server/wh_server_port.c`.
4. Edit `client/wolfhsm_cfg.h` and `server/wolfhsm_cfg.h` with your
   platform's configuration values.
5. Edit `client/user_settings.h` and `server/user_settings.h` with the
   wolfSSL features your application requires.
6. Create a build system (Makefile, CMake, IDE project, etc.) that compiles
   the generic examples together with your port. See `port/posix/` for a
   Makefile-based reference.

See `docs/draft/porting.md` for a detailed porting guide.
