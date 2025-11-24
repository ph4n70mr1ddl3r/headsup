"""
Toy zero-knowledge-style set membership with deterministic nullifiers.

This script keeps the cryptography intentionally simple and self contained:
- Accounts are backed by a Schnorr-style key pair over a large prime field.
- Membership is proven with a sparse Merkle tree so the construction can
  scale up to 2**26 (~67M) leaves without material code changes.
- Knowledge of the private key is proven with a non-interactive Schnorr proof
  (Fiat-Shamir). The verifier only sees the public key and proof.
- A deterministic nullifier prevents double-use per context without revealing
  the private key.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

# Field parameters for the Schnorr proof. Using the secp256k1 prime keeps values
# in the familiar Ethereum range while remaining fully self contained.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = 5  # Simple generator candidate; sufficient for this demo.

# A tree height of 26 covers ~67M leaves. Lower heights work for small demos.
TREE_HEIGHT = 26


def sha3(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def int_to_bytes(value: int, length: int = 32) -> bytes:
    return value.to_bytes(length, byteorder="big")


def bytes_to_hex(data: bytes) -> str:
    return "0x" + data.hex()


def hash_leaf(address: bytes, index: int) -> bytes:
    return sha3(b"leaf:" + address + int_to_bytes(index, 4))


def hash_node(left: bytes, right: bytes) -> bytes:
    return sha3(b"node:" + left + right)


def nullifier(address: bytes, context: bytes) -> bytes:
    return sha3(b"nullifier:" + context + address)


def derive_public_key(privkey: int) -> int:
    return pow(G, privkey, P)


def derive_address(pubkey: int) -> bytes:
    # Mimic an Ethereum-like address: last 20 bytes of Keccak-256(pubkey).
    return sha3(int_to_bytes(pubkey))[-20:]


@dataclass(frozen=True)
class Account:
    name: str
    private_key: int
    public_key: int
    address: bytes
    index: int


def make_account(name: str, privkey_hex: str, index: int) -> Account:
    privkey = int(privkey_hex, 16) % P
    pubkey = derive_public_key(privkey)
    address = derive_address(pubkey)
    return Account(name=name, private_key=privkey, public_key=pubkey, address=address, index=index)


class SparseMerkleTree:
    def __init__(self, height: int = TREE_HEIGHT):
        self.height = height
        self.default_hashes = self._compute_default_hashes()
        self.leaves: Dict[int, bytes] = {}
        self.levels: List[Dict[int, bytes]] = []

    def _compute_default_hashes(self) -> List[bytes]:
        defaults = [sha3(b"default_leaf")]
        for _ in range(self.height):
            defaults.append(hash_node(defaults[-1], defaults[-1]))
        return defaults

    def add_leaf(self, index: int, leaf_hash: bytes) -> None:
        if index >= 2**self.height:
            raise ValueError("index out of range for configured tree height")
        self.leaves[index] = leaf_hash

    def build(self) -> None:
        level_nodes: Dict[int, bytes] = dict(self.leaves)
        self.levels = [level_nodes]
        for level in range(self.height):
            parent_nodes: Dict[int, bytes] = {}
            parent_indices = {idx // 2 for idx in level_nodes.keys()}
            for parent_idx in parent_indices:
                left = level_nodes.get(parent_idx * 2, self.default_hashes[level])
                right = level_nodes.get(parent_idx * 2 + 1, self.default_hashes[level])
                if left == self.default_hashes[level] and right == self.default_hashes[level]:
                    continue
                parent_nodes[parent_idx] = hash_node(left, right)
            self.levels.append(parent_nodes)
            level_nodes = parent_nodes

    def root(self) -> bytes:
        if not self.levels:
            self.build()
        return self.levels[-1].get(0, self.default_hashes[self.height])

    def prove_membership(self, index: int) -> List[bytes]:
        if not self.levels:
            self.build()
        path: List[bytes] = []
        idx = index
        for level in range(self.height):
            sibling_idx = idx ^ 1
            sibling_hash = self.levels[level].get(sibling_idx, self.default_hashes[level])
            path.append(sibling_hash)
            idx //= 2
        return path


def verify_membership(root: bytes, address: bytes, index: int, path: Iterable[bytes], height: int) -> bool:
    computed = hash_leaf(address, index)
    idx = index
    for level, sibling in enumerate(path):
        if idx % 2 == 0:
            computed = hash_node(computed, sibling)
        else:
            computed = hash_node(sibling, computed)
        idx //= 2
    expected_root = computed
    return expected_root == root


def schnorr_prove(privkey: int, pubkey: int, context: bytes) -> Tuple[int, int]:
    # Fiat-Shamir: challenge binds commitment and context.
    r = secrets.randbelow(P - 1) + 1
    commit = pow(G, r, P)
    challenge = int.from_bytes(sha3(int_to_bytes(commit) + int_to_bytes(pubkey) + context), "big") % (P - 1)
    response = (r + challenge * privkey) % (P - 1)
    return commit, response


def schnorr_verify(pubkey: int, proof: Tuple[int, int], context: bytes) -> bool:
    commit, response = proof
    challenge = int.from_bytes(sha3(int_to_bytes(commit) + int_to_bytes(pubkey) + context), "big") % (P - 1)
    lhs = pow(G, response, P)
    rhs = (commit * pow(pubkey, challenge, P)) % P
    return lhs == rhs


def build_tree(accounts: Iterable[Account], height: int = TREE_HEIGHT) -> SparseMerkleTree:
    tree = SparseMerkleTree(height=height)
    for account in accounts:
        tree.add_leaf(account.index, hash_leaf(account.address, account.index))
    tree.build()
    return tree


def create_proof(account: Account, tree: SparseMerkleTree, context: bytes) -> Dict[str, object]:
    membership_path = tree.prove_membership(account.index)
    root = tree.root()
    knowledge_proof = schnorr_prove(account.private_key, account.public_key, context)
    account_nullifier = nullifier(account.address, context)
    return {
        "address": bytes_to_hex(account.address),
        "index": account.index,
        "public_key": account.public_key,
        "merkle_root": bytes_to_hex(root),
        "membership_path": [bytes_to_hex(x) for x in membership_path],
        "nullifier": bytes_to_hex(account_nullifier),
        "schnorr": {"commit": knowledge_proof[0], "response": knowledge_proof[1]},
    }


def verify_proof(proof: Dict[str, object], context: bytes, height: int = TREE_HEIGHT) -> bool:
    address_bytes = bytes.fromhex(proof["address"][2:])
    pubkey = int(proof["public_key"])
    if derive_address(pubkey) != address_bytes:
        return False

    root = bytes.fromhex(proof["merkle_root"][2:])
    path = [bytes.fromhex(x[2:]) for x in proof["membership_path"]]
    if not verify_membership(root, address_bytes, int(proof["index"]), path, height):
        return False

    expected_nullifier = nullifier(address_bytes, context)
    if bytes_to_hex(expected_nullifier) != proof["nullifier"]:
        return False

    schnorr_tuple = (int(proof["schnorr"]["commit"]), int(proof["schnorr"]["response"]))
    return schnorr_verify(pubkey, schnorr_tuple, context)


def pack_proof_blob(proof: Dict[str, object]) -> bytes:
    """
    Bundle all proof internals into a single opaque blob. This mirrors how a
    SNARK/STARK proof would look to an application: only the root, nullifier,
    and the opaque proof data are revealed to the outside.
    """
    parts: List[bytes] = [
        bytes.fromhex(proof["merkle_root"][2:]),
        bytes.fromhex(proof["nullifier"][2:]),
        int_to_bytes(proof["public_key"]),
        int_to_bytes(proof["schnorr"]["commit"]),
        int_to_bytes(proof["schnorr"]["response"]),
        int_to_bytes(proof["index"], 4),
    ]
    for sibling in proof["membership_path"]:
        parts.append(bytes.fromhex(sibling[2:]))
    return b"".join(parts)


def unpack_proof_blob(blob: bytes, path_length: int) -> Dict[str, object]:
    # Reverse the packing routine; the format is deterministic for this demo.
    cursor = 0
    def take(size: int) -> bytes:
        nonlocal cursor
        chunk = blob[cursor : cursor + size]
        cursor += size
        return chunk

    merkle_root = take(32)
    nullifier_bytes = take(32)
    public_key = int.from_bytes(take(32), "big")
    commit = int.from_bytes(take(32), "big")
    response = int.from_bytes(take(32), "big")
    index = int.from_bytes(take(4), "big")
    path = [take(32) for _ in range(path_length)]
    address = derive_address(public_key)

    return {
        "merkle_root": bytes_to_hex(merkle_root),
        "nullifier": bytes_to_hex(nullifier_bytes),
        "public_key": public_key,
        "schnorr": {"commit": commit, "response": response},
        "index": index,
        "address": bytes_to_hex(address),
        "membership_path": [bytes_to_hex(x) for x in path],
    }


def create_private_membership_proof(account: Account, tree: SparseMerkleTree, context: bytes) -> Dict[str, object]:
    # Generate a proof but expose only an opaque blob plus public root/nullifier.
    raw = create_proof(account, tree, context)
    blob = pack_proof_blob(raw)
    public_view = {
        "merkle_root": raw["merkle_root"],
        "nullifier": raw["nullifier"],
        "proof_blob": bytes_to_hex(blob),
    }
    private_to_verifier = {
        "blob": blob,
        "path_length": len(raw["membership_path"]),
    }
    return {"public": public_view, "verifier_payload": private_to_verifier}


def verify_private_membership(proof_package: Dict[str, object], context: bytes) -> bool:
    blob = proof_package["verifier_payload"]["blob"]
    path_len = proof_package["verifier_payload"]["path_length"]
    unpacked = unpack_proof_blob(blob, path_len)

    # Use the public nullifier/root from the unpacked blob; they must match.
    provided_root = proof_package["public"]["merkle_root"]
    provided_nullifier = proof_package["public"]["nullifier"]
    if provided_root != unpacked["merkle_root"] or provided_nullifier != unpacked["nullifier"]:
        return False

    return verify_proof(unpacked, context, height=TREE_HEIGHT)


def demo() -> None:
    """
    Run two cycles:
    1) A transparent demo that shows all internals (for debugging/education).
    2) A "private" cycle that only reveals root, nullifier, and an opaque proof blob.
    """
    context = b"airdrop-epoch-7"
    sample_accounts = [
        make_account("Treasury multisig signer", "0x9c8bf6d5f3a1e0c4f7d3293a2fbf4e912c6d9edccb7c2d1fb3a524f091e0d311", 3),
        make_account("Operations hot wallet", "0x15cdd773c8d9b9f08f35c75ca9f41248ee0698a2f4b63de90e01d1a9a5f2a123", 17),
        make_account("Analytics node", "0x7b9fc2e4a1d8c3e5f47aa2c1e5b2c1d67e89cdef2b457a1234e56a7b9c0d4e78", 42),
        make_account("QA wallet", "0x2d6f1c3b5a7e9d1f3c5b7a9d2e4f6a8b1c3d5e7f9a1b3c5d7e9f1a3c5b7d9e1f", 2047),
    ]

    tree = build_tree(sample_accounts, height=TREE_HEIGHT)
    root = tree.root()

    print("=== Transparent demo (for clarity) ===")
    prover_account = sample_accounts[1]
    proof = create_proof(prover_account, tree, context)
    is_valid = verify_proof(proof, context, height=TREE_HEIGHT)

    print("Merkle root:", bytes_to_hex(root))
    print("Context:", context.decode())
    print("Prover claims membership for:", prover_account.name)
    print("  Address:", proof["address"])
    print("  Public key:", proof["public_key"])
    print("  Index:", proof["index"])
    print("  Nullifier:", proof["nullifier"])
    print("  Membership path length:", len(proof["membership_path"]))
    print("Verification result:", "valid ✅" if is_valid else "invalid ❌")
    print()

    print("=== Private-style demo (opaque proof blob) ===")
    private_proof = create_private_membership_proof(prover_account, tree, context)
    public_view = private_proof["public"]
    print("Merkle root:", public_view["merkle_root"])
    print("Context:", context.decode())
    print("Nullifier:", public_view["nullifier"])
    print("Opaque proof size (bytes):", len(bytes.fromhex(public_view["proof_blob"][2:])))

    private_valid = verify_private_membership(private_proof, context)
    print("Verification result:", "valid ✅" if private_valid else "invalid ❌")


if __name__ == "__main__":
    demo()
