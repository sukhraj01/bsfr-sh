"""Foundation layer: config, logging, seeding, canonical serialization.

`util` depends on nothing else in this package (docs/ARCHITECTURE.md). Submodules are imported
explicitly by their users — `from bsfr_sh.util import logging as log` — rather than re-exported
here, so that importing one does not drag in NumPy.
"""
