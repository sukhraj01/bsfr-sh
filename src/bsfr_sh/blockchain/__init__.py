"""Blockchain data structures: `Transaction`, `BlockDraft`/`Block`, `Chain`.

Depends on `crypto` and `util`, and on nothing above it (docs/ARCHITECTURE.md §Dependency
direction). It knows nothing about pBFT, cloud servers or the honeypot — consensus is M2b and
takes blocks as input; where this layer needs "who proposed this", it is a parameter.

Submodules are imported explicitly by their users, matching `util` and `crypto`.
"""
