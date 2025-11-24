"""
Generate and verify a membership proof from a random account in accounts.csv.

Usage:
  python3 proof_from_csv.py --accounts-file accounts.csv --context airdrop-epoch-7

The script:
  1) Loads all rows from the CSV (fields: index,name,private_key,...).
  2) Builds the sparse Merkle tree from those accounts.
  3) Picks a random account (or a specific one via --index) and creates an
     opaque membership proof with deterministic nullifier.
  4) Verifies the proof and prints the result.
"""

from __future__ import annotations

import argparse
import csv
import secrets
import sys
from typing import List

from zkp_membership import (
    Account,
    TREE_HEIGHT,
    build_tree,
    create_private_membership_proof,
    verify_private_membership,
    make_account,
)


def load_accounts(path: str) -> List[Account]:
    accounts: List[Account] = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            idx = int(row["index"])
            priv = row["private_key"]
            name = row.get("name", f"Account {idx}")
            accounts.append(make_account(name, priv, idx))
    return accounts


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and verify a membership proof from accounts.csv.")
    parser.add_argument("--accounts-file", default="accounts.csv", help="Path to CSV with accounts.")
    parser.add_argument("--context", default="airdrop-epoch-7", help="Context string for the nullifier.")
    parser.add_argument("--index", type=int, help="Optional index of the account to prove; defaults to random.")
    args = parser.parse_args()

    accounts = load_accounts(args.accounts_file)
    if not accounts:
        print("No accounts found in CSV.")
        return 1

    tree = build_tree(accounts, height=TREE_HEIGHT)
    chosen = None
    if args.index is not None:
        for acct in accounts:
            if acct.index == args.index:
                chosen = acct
                break
        if chosen is None:
            print(f"Index {args.index} not found in CSV.")
            return 1
    else:
        chosen = secrets.choice(accounts)

    context_bytes = args.context.encode()
    proof_pkg = create_private_membership_proof(chosen, tree, context_bytes)
    is_valid = verify_private_membership(proof_pkg, context_bytes)

    public_view = proof_pkg["public"]
    print("Context:", args.context)
    print("Merkle root:", public_view["merkle_root"])
    print("Nullifier:", public_view["nullifier"])
    print("Prover account name:", chosen.name)
    print("Prover index:", chosen.index)
    print("Opaque proof size (bytes):", len(bytes.fromhex(public_view["proof_blob"][2:])))
    print("Verification result:", "valid ✅" if is_valid else "invalid ❌")
    if not is_valid:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
