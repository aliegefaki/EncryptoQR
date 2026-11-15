#!/usr/bin/env python3
"""Encrypted QR Optimization Tool: research/benchmark edition.

Evaluates up to 600 configurations per UTF-8 text input, subject to optional
algorithm constraints and stage omission, and reports all feasible configurations attaining the
minimum QR version at each error correction level. Uses QR byte mode, matching
the article's benchmark.

WARNING: Fixed keys and IVs/nonces are deliberately used to reproduce the
research experiment. Do not use this program for real-world encryption.
It calculates QR versions; it does not produce deployable encrypted QR codes.
"""

from __future__ import annotations

import argparse
import bz2
import lzma
import sys
import zlib
from collections import Counter
from dataclasses import dataclass

try:
    import brotli
    import qrcode
    import zstandard as zstd
    from Crypto.Cipher import ChaCha20_Poly1305
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from qrcode.util import BIT_LIMIT_TABLE
except ImportError as exc:
    raise SystemExit(
        f"Missing dependency: {exc}\n"
        "Install with: python -m pip install qrcode brotli zstandard cryptography pycryptodome"
    ) from exc

KEY = b"\x10" * 32  # Benchmark only.
OVERFLOW = "40+"
ERROR_LEVELS = {
    "L": qrcode.constants.ERROR_CORRECT_L,
    "M": qrcode.constants.ERROR_CORRECT_M,
    "Q": qrcode.constants.ERROR_CORRECT_Q,
    "H": qrcode.constants.ERROR_CORRECT_H,
}


def pad_pkcs7(data: bytes) -> bytes:
    length = 16 - len(data) % 16
    return data + bytes([length]) * length


def encrypt_aes(data: bytes, mode) -> bytes:
    encryptor = Cipher(algorithms.AES(KEY), mode).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def encrypt_aes_gcm(data: bytes) -> bytes:
    nonce = b"\x01" * 12
    return nonce + AESGCM(KEY).encrypt(nonce, data, None)


def encrypt_chacha20_poly1305(data: bytes) -> bytes:
    nonce = b"\x02" * 12
    return nonce + ChaCha20Poly1305(KEY).encrypt(nonce, data, None)


def encrypt_aes_ctr(data: bytes) -> bytes:
    iv = b"\x03" * 16
    return iv + encrypt_aes(data, modes.CTR(iv))


def encrypt_aes_cbc(data: bytes) -> bytes:
    iv = b"\x04" * 16
    return iv + encrypt_aes(pad_pkcs7(data), modes.CBC(iv))


def encrypt_xchacha20_poly1305(data: bytes) -> bytes:
    nonce = b"\x05" * 24
    cipher = ChaCha20_Poly1305.new(key=KEY, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + ciphertext + tag


COMPRESSION_ALGORITHMS = {
    "zlib": zlib.compress,
    "bz2": bz2.compress,
    "lzma": lzma.compress,
    "zstd": lambda data: zstd.ZstdCompressor().compress(data),
    "brotli": brotli.compress,
}

PRE_ENCRYPTION_ALGORITHMS = {
    "AES-ECB": lambda data: encrypt_aes(pad_pkcs7(data), modes.ECB()),
    "AES-CBC (Fixed IV)": lambda data: encrypt_aes(pad_pkcs7(data), modes.CBC(b"\x00" * 16)),
    "AES-CTR (Fixed Nonce)": lambda data: encrypt_aes(data, modes.CTR(b"\x00" * 16)),
    "XOR": lambda data: bytes(byte ^ 0x42 for byte in data),
    "Caesar": lambda data: bytes((byte + 3) % 256 for byte in data),
}

FINAL_ENCRYPTION_ALGORITHMS = {
    "AES-GCM": encrypt_aes_gcm,
    "ChaCha20-Poly1305": encrypt_chacha20_poly1305,
    "AES-CTR": encrypt_aes_ctr,
    "AES-CBC": encrypt_aes_cbc,
    "XChaCha20-Poly1305": encrypt_xchacha20_poly1305,
}

# Selection categories restrict the search space; they are not security scores.
PRE_ENCRYPTION_OPTIONS = {
    "Any": ("None", *PRE_ENCRYPTION_ALGORITHMS),
    "None": ("None",),
    "AES-based Only": ("AES-ECB", "AES-CBC (Fixed IV)", "AES-CTR (Fixed Nonce)"),
    "Byte-wise Substitution Only (XOR / Caesar)": ("XOR", "Caesar"),
    **{name: (name,) for name in PRE_ENCRYPTION_ALGORITHMS},
}
COMPRESSION_OPTIONS = {
    "Any": tuple(COMPRESSION_ALGORITHMS),
    "None": ("None",),
    **{name: (name,) for name in COMPRESSION_ALGORITHMS},
}
ENCRYPTION_OPTIONS = {
    "Any": tuple(FINAL_ENCRYPTION_ALGORITHMS),
    "None": ("None",),
    "AEAD Only": ("AES-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305"),
    **{name: (name,) for name in FINAL_ENCRYPTION_ALGORITHMS},
}


def qr_version(payload: bytes, error_level: int) -> int | str:
    """Smallest QR version fitting the payload in 8-bit byte mode."""
    data_bits = len(payload) * 8
    for version in range(1, 41):
        count_bits = 8 if version <= 9 else 16
        required_bits = 4 + count_bits + data_bits
        if required_bits <= BIT_LIMIT_TABLE[error_level][version]:
            return version
    return OVERFLOW


@dataclass(frozen=True)
class Result:
    scenario: str
    pre_encryption: str
    compression: str
    encryption: str
    error_level: str
    qr_version: int | str
    original_bytes: int
    pre_encrypted_bytes: int
    compressed_bytes: int
    encrypted_bytes: int


def evaluate(text: str, pre_encryption: str = "Any", compression: str = "Any",
             encryption: str = "Any") -> list[Result]:
    """Evaluate all permitted pipelines at each of four error correction levels."""
    if not text:
        raise ValueError("Input text must not be empty.")
    pre_names = PRE_ENCRYPTION_OPTIONS[pre_encryption]
    comp_names = COMPRESSION_OPTIONS[compression]
    enc_names = ENCRYPTION_OPTIONS[encryption]
    raw = text.encode("utf-8")
    results = []
    pipelines = [("S1", "None", raw)] if "None" in pre_names else []
    for name in pre_names:
        if name != "None":
            pipelines.append(("S2", name, PRE_ENCRYPTION_ALGORITHMS[name](raw)))

    for scenario, pre_name, pre_data in pipelines:
        for comp_name in comp_names:
            compressed = pre_data if comp_name == "None" else COMPRESSION_ALGORITHMS[comp_name](pre_data)
            for enc_name in enc_names:
                encrypted = compressed if enc_name == "None" else FINAL_ENCRYPTION_ALGORITHMS[enc_name](compressed)
                for level_name, level in ERROR_LEVELS.items():
                    results.append(Result(
                        scenario, pre_name, comp_name, enc_name, level_name,
                        qr_version(encrypted, level), len(raw), len(pre_data),
                        len(compressed), len(encrypted),
                    ))

    counts = Counter((row.scenario, row.error_level) for row in results)
    expected = Counter((scenario, level) for scenario, _, _ in pipelines
                       for _comp in comp_names for _enc in enc_names
                       for level in ERROR_LEVELS)
    if counts != expected or len(results) != sum(expected.values()):
        raise RuntimeError(f"Incomplete evaluation: expected {sum(expected.values())} configurations.")
    return results


def best_results(results: list[Result], level: str) -> list[Result]:
    feasible = [row for row in results if row.error_level == level
                and isinstance(row.qr_version, int)]
    if not feasible:
        return []
    minimum = min(row.qr_version for row in feasible)
    return [row for row in feasible if row.qr_version == minimum]


def print_results(results: list[Result], pre_encryption: str = "Any",
                  compression: str = "Any", encryption: str = "Any") -> None:
    print("\n=== QR Optimization Results ===")
    print(f"Input size: {results[0].original_bytes} bytes (UTF-8)")
    print(f"Constraints: pre-encryption = {pre_encryption}; compression = {compression}; encryption = {encryption}")
    if encryption == "None":
        print("Note: Final encryption is disabled. Results represent a comparison baseline.")
    counts = Counter(row.scenario for row in results)
    print(f"Total configurations: {len(results)} (S1: {counts['S1']}; S2: {counts['S2']})")
    for level in ERROR_LEVELS:
        subset = [row for row in results if row.error_level == level]
        winners = best_results(results, level)
        overflow = sum(row.qr_version == OVERFLOW for row in subset)
        print(f"\n--- Error correction level {level} ---")
        print(f"Configurations: {len(subset)} | Overflow: {overflow}")
        if not winners:
            print("No feasible configuration found for this error correction level.")
            continue
        print(f"Minimum QR version: {winners[0].qr_version}")
        print(f"Optimal configurations: {len(winners)}")
        print(f"{'Scenario':<8} | {'Pre-encryption':<22} | {'Compression':<11} | "
              f"{'Encryption':<20} | {'QR':>2} | Bytes (raw/pre/comp/final)")
        for row in winners:
            print(f"{row.scenario:<8} | {row.pre_encryption:<22} | "
                  f"{row.compression:<11} | {row.encryption:<20} | "
                  f"{row.qr_version:>2} | {row.original_bytes}/{row.pre_encrypted_bytes}/"
                  f"{row.compressed_bytes}/{row.encrypted_bytes}")


def select_option(title: str, options: dict[str, tuple[str, ...]]) -> str:
    names = tuple(options)
    print(f"\n{title}:")
    for i, name in enumerate(names, 1):
        print(f"  {i}. {name}")
    while True:
        choice = input("Select an option [Enter = Any]: ").strip()
        if not choice:
            return "Any"
        if choice.isascii() and choice.isdecimal() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        print(f"Invalid selection. Enter a number from 1 to {len(names)}.")


def print_introduction() -> None:
    print("=== Encrypted QR Optimization Tool ===")
    print("Research tool: finds minimum QR versions in byte mode for levels L, M, Q and H.")
    print("Selection guide:")
    print("  Any  - evaluate all five algorithms in the selected stage;")
    print("         for pre-encryption, also include the no-pre-encryption case.")
    print("  None - skip the selected stage (the bytes pass through unchanged).")
    print("  AES-based Only - restrict pre-encryption to the three AES modes.")
    print("  Byte-wise Substitution Only - restrict pre-encryption to XOR and Caesar.")
    print("  AEAD Only - restrict final encryption to AES-GCM, ChaCha20-Poly1305,")
    print("              and XChaCha20-Poly1305 (authenticated encryption).")
    print("  Press Enter at any selection prompt to choose Any.")
    print("  Any / Any / Any evaluates the original 600 benchmark configurations.")
    print("  None for compression or final encryption enables comparison baselines.")
    print("Security note: fixed benchmark keys and nonces/IVs are not safe for")
    print("real-world encryption; the tool estimates QR versions, not security scores.\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("text", nargs="?", help="UTF-8 text (quote it if it contains spaces)")
    args = parser.parse_args()
    try:
        print_introduction()
        text = args.text if args.text is not None else input("Enter text to evaluate: ")
        if not text:
            raise ValueError("Input text must not be empty.")
        pre_encryption = select_option("Pre-encryption", PRE_ENCRYPTION_OPTIONS)
        compression = select_option("Compression", COMPRESSION_OPTIONS)
        encryption = select_option("Final encryption", ENCRYPTION_OPTIONS)
        results = evaluate(text, pre_encryption, compression, encryption)
        print_results(results, pre_encryption, compression, encryption)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
