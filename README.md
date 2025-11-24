ZKP-style set membership demo
============================

This repository contains a small, self-contained simulation of a set membership proof with a deterministic nullifier. A prover demonstrates:
- Their account address sits inside a sparse Merkle tree representing all allowed accounts.
- They know the private key corresponding to that account (Schnorr-style knowledge proof).
- They can emit a deterministic nullifier tied to a context (to prevent reuse).

The cryptography is deliberately lightweight and lives entirely in Python's standard library. The tree uses a sparse Merkle layout sized for up to 2\*\*26 leaves (~67M accounts), so you can scale the demo without changing the shape of the code.

How to run
----------

```bash
python zkp_membership.py
```

You'll see:
- The Merkle root of the configured account set.
- The context string bound into the proof.
- Details of a single prover's claim (address, index, nullifier, path length).
- Verification result.

The script runs two passes:
- Transparent: prints all details (good for understanding the flow).
- Private-style: only shows `root`, `context`, `nullifier`, and an opaque proof blob; verification consumes the blob without revealing which account or path was used.

Key files
---------

- `zkp_membership.py` — core implementation and a runnable demo.

How it works (high level)
-------------------------

- Accounts: Each account has a private key `sk`, public key `pk = G^sk mod P`, and an Ethereum-like address `addr = keccak(pk)[12:]`.
- Membership: Addresses are placed into a sparse Merkle tree. Leaves are `keccak("leaf:" || address || index)`. Default hashes let the tree cover up to 2\*\*26 slots without storing empty nodes.
- Knowledge of `sk`: A non-interactive Schnorr proof (Fiat-Shamir) shows possession of `sk` without revealing it. The verifier checks `G^s = commit * pk^challenge mod P`.
- Nullifier: `keccak("nullifier:" || context || address)` binds the account to a specific use-context (e.g., an epoch). The same account/context pair always yields the same nullifier, enabling double-spend detection.

Extending to larger sets
------------------------

- The default tree height is 26 (≈64M leaves). Adjust `TREE_HEIGHT` in `zkp_membership.py` upward if you need more room. Because the tree is sparse and default hashes are reused, you do not need to materialize all empty leaves.
- To add more accounts, create more `Account` instances with distinct indexes within the tree's range and rebuild the tree.
- In a production setting, you would replace the ad-hoc primitives with audited libraries (e.g., a real Keccak, secp256k1 signatures, and a SNARK/STARK membership proof), but the structure and data flow would remain similar.
