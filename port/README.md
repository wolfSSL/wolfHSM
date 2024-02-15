# wolfHSM Ports

Each of the implemented port-specific code and resources are kept in port directories organized first by platform vendor and possibly further by product.  Each of the ports is expected to provide the glue logic between wolfHSM abtractions (transport, NVM objects, flash, and cryptocb) and the native or vendor-provided libraries.

Due to the sensitive nature of some platform code, not all of the source and glue logic can be provided in this public repo, but the base directories of these ports are listed here with any public interfaces that can be provided and additional contact information.
