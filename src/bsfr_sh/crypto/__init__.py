"""Cryptographic primitives: hashing, Merkle trees, ECDSA, AEAD, key wrapping, sessions.

`crypto` depends on `util` and on nothing else inside the package (docs/ARCHITECTURE.md
§Dependency direction). It knows nothing about `Block`, `Transaction` or pBFT — those consume it
in M2. Where a primitive here needs to bind protocol structure, it takes raw bytes or a plain
mapping so the dependency cannot invert.

Submodules are imported explicitly by their users (``from bsfr_sh.crypto import hashing``) rather
than re-exported here, matching `util`'s convention.
"""
