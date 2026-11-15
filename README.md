# EncryptoQR

EncryptoQR is a standalone Python research tool for QR code version optimization under user-defined compression and encryption constraints. It evaluates the permitted algorithm combinations and identifies every configuration that attains the minimum feasible QR version at each of the four standard error correction levels (L, M, Q, H).

## Installation

The reported experimental environment is Python 3.14.10. The direct third-party dependencies are pinned in `requirements.txt` to the versions used in that environment.

From the repository directory, install the dependencies:

```sh
python -m pip install -r requirements.txt
```

`zlib`, `bz2`, and `lzma` are provided by the Python standard library and do not require separate installation. No graphical interface, additional Python script, or external service is required.

## Usage

```sh
python qr_optimizer.py
```

Enter a non-empty text input, followed by the desired pre-encryption, compression, and final encryption options. Press Enter at any selection prompt to select `Any`.

### Available options

| Stage | Individual algorithms | Additional selections |
| --- | --- | --- |
| Pre-encryption | AES-ECB, AES-CBC (Fixed IV), AES-CTR (Fixed Nonce), XOR, Caesar | Any, None, AES-based Only, Byte-wise Substitution Only |
| Compression | zlib, bz2, lzma, zstd, brotli | Any, None |
| Final encryption | AES-GCM, ChaCha20-Poly1305, AES-CTR, AES-CBC, XChaCha20-Poly1305 | Any, None, AEAD Only |

- `Any` evaluates all five algorithms in the selected stage. For pre-encryption, it additionally includes the case without pre-encryption.
- `None` skips the selected stage, passing the bytes through unchanged.
- `AES-based Only` restricts pre-encryption to the three AES-based methods.
- `Byte-wise Substitution Only` restricts pre-encryption to XOR and Caesar.
- `AEAD Only` restricts final encryption to AES-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305.

The default selection (`Any / Any / Any`) reproduces the original experimental search space: 100 configurations without pre-encryption (S1) and 500 with pre-encryption (S2), for a total of 600 configurations across the four error correction levels. Explicitly skipping compression or final encryption provides additional comparison baselines without changing that default search space.

### Example

To evaluate `Hello QR` without pre-encryption and with authenticated final encryption, select `None / Any / AEAD Only`. The tool evaluates 60 configurations (5 compression algorithms × 3 AEAD algorithms × 4 error correction levels).

For each error correction level, the output reports the number of evaluated configurations, the number exceeding QR capacity, the minimum feasible QR version, and all combinations attaining that version. The byte counts correspond to the original, pre-encrypted, compressed, and final payloads.

## Method and limitations

The input is encoded as UTF-8. The tool applies the selected stages in order and determines the minimum QR version from the byte-mode capacity table provided by `qrcode`. Final encryption overhead (IV or nonce, authentication tag where applicable, and padding where applicable) is included in the payload size. Configurations that exceed version 40 are excluded from the set of optimal feasible results.

The objective is to minimize QR version within the selected constraints. Algorithm categories are filters, not quantitative security scores. The tool does not generate deployable QR images or implement a secure end-to-end encryption protocol.

**Security warning:** the fixed key and fixed IV/nonce values are used solely to preserve reproducible benchmark conditions. They are unsuitable for real-world encryption. The `None` option for final encryption provides a comparison baseline rather than a guarantee of confidentiality or authentication.

## License

MIT License; see [LICENSE](LICENSE).
