# AIvantGuard common library for common functions

The code requires a PQC prerequisite from:
https://github.com/open-quantum-safe/liboqs-python

Install using the given instructions.

# Module: `aivantguard-common/utility/advanced_encrypt.py`

This module provides advanced cryptographic operations combining classical and post-quantum algorithms for enhanced security. It includes functionalities for hybrid key exchange (ECDH + Kyber KEM), authenticated encryption (AES-GCM + HMAC-SHA3-512), digital signatures (ECDSA), and password-based key derivation (Argon2id).

## Constants

*   `EC_CURVE`: `ec.SECP521R1()` - The elliptic curve used for ECDH and ECDSA.
*   `ECC_KEY_SIZE_BYTES`: `int` - The size of ECC keys in bytes, derived from `EC_CURVE`.
*   `HASH_ALGORITHM`: `hashes.SHA3_512` - The hash algorithm used for various operations (HKDF, HMAC, ECDSA).
*   `KEM_ALGORITHM`: `"Kyber1024"` - The post-quantum Key Encapsulation Mechanism algorithm used.
*   `HKDF_INFO_PREFIX`: `bytes` - A prefix used in the HKDF info string for domain separation.
*   `AES_KEY_BYTES`: `32` - The required length for AES keys (AES-256).
*   `HMAC_KEY_BYTES`: `32` - The required length for HMAC keys.
*   `DERIVED_KEY_BYTES`: `64` - The total length of the key derived via HKDF (AES key + HMAC key).
*   `SALT_BYTES`: `16` - The default and minimum length for cryptographic salts.
*   `AES_NONCE_BYTES`: `12` - The length of the nonce used for AES-GCM.
*   `HMAC_TAG_BYTES`: `64` - The length of the HMAC tag (matches the digest size of `HASH_ALGORITHM`).
*   `ARGON2_DEFAULT_TIME_COST`: `3` - Default time cost parameter for Argon2id.
*   `ARGON2_DEFAULT_MEMORY_COST`: `65536` - Default memory cost parameter (in KiB) for Argon2id.
*   `ARGON2_DEFAULT_PARALLELISM`: `4` - Default parallelism parameter for Argon2id.
*   `ARGON2_DEFAULT_HASH_LEN`: `32` - Default output key length for Argon2id.
*   `ARGON2_TYPE`: `Argon2Type.ID` - The Argon2 variant used (Argon2id).

## Data Structures

### `EccKeyPair(NamedTuple)`

Represents an Elliptic Curve Cryptography (ECC) key pair.

*   **Fields:**
    *   `private_key` (`ec.EllipticCurvePrivateKey`): The private key object.
    *   `public_key` (`ec.EllipticCurvePublicKey`): The public key object.
    *   `private_pem` (`bytes`): The private key serialized in PEM format (PKCS8, unencrypted).
    *   `public_pem` (`bytes`): The public key serialized in PEM format (SubjectPublicKeyInfo).
    *   `public_hash` (`str`): The SHA3-512 hash of the public PEM key (hex digest).

### `KemKeyPair(NamedTuple)`

Represents a Key Encapsulation Mechanism (KEM) key pair.

*   **Fields:**
    *   `kem_instance` (`oqs.KeyEncapsulation`): The initialized KEM instance holding the private key material. **Note:** The user must call `kem_instance.free()` when this key pair is no longer needed to release associated resources.
    *   `public_key` (`bytes`): The public key bytes generated by the KEM.

## Functions

### `generate_ecc_keypair()`

Generates an ECC key pair using the predefined curve (`EC_CURVE`).

*   **Args:**
    *   None
*   **Returns:**
    *   `EccKeyPair`: A named tuple containing the generated private key, public key, their PEM representations, and the hash of the public key PEM.
*   **Raises:**
    *   `ValueError`: If the `EC_CURVE` constant is not a valid `EllipticCurve` instance.

### `generate_kem_keypair()`

Generates a KEM key pair using the predefined algorithm (`KEM_ALGORITHM`).

*   **Args:**
    *   None
*   **Returns:**
    *   `KemKeyPair`: A named tuple containing the KEM instance (with private key material) and the public key bytes.
*   **Raises:**
    *   `ValueError`: If the `KEM_ALGORITHM` constant is not a valid string.
    *   `RuntimeError`: If the underlying OQS KEM key pair generation fails.

### `generate_salt(length=SALT_BYTES)`

Generates a cryptographically secure random salt.

*   **Args:**
    *   `length` (`int`, optional): The desired length of the salt in bytes. Defaults to `SALT_BYTES` (16). Must be at least 16.
*   **Returns:**
    *   `bytes`: A byte string containing the random salt.
*   **Raises:**
    *   `ValueError`: If `length` is less than 16.

### `get_hash(data_for_hash)`

Computes the SHA3-512 hash of the input data.

*   **Args:**
    *   `data_for_hash` (`bytes`): The byte string to hash.
*   **Returns:**
    *   `str`: The hexadecimal representation of the SHA3-512 hash digest.
*   **Raises:**
    *   `TypeError`: If `data_for_hash` is not a bytes object.

### `derive_shared_key(own_ecc_private_key, peer_ecc_public_key, own_kem_instance, peer_kem_public_key, peer_public_key_hash, own_public_key_hash, salt, key_length=DERIVED_KEY_BYTES)`

Derives a shared secret key using a hybrid approach (ECDH + KEM encapsulation) and HKDF. This function is typically called by the party initiating the key exchange.

*   **Args:**
    *   `own_ecc_private_key` (`ec.EllipticCurvePrivateKey`): The initiator's ECC private key.
    *   `peer_ecc_public_key` (`ec.EllipticCurvePublicKey`): The responder's ECC public key.
    *   `own_kem_instance` (`oqs.KeyEncapsulation`): The initiator's KEM instance (containing their private key).
    *   `peer_kem_public_key` (`bytes`): The responder's KEM public key.
    *   `peer_public_key_hash` (`str`): The hash of the responder's public ECC key PEM.
    *   `own_public_key_hash` (`str`): The hash of the initiator's public ECC key PEM.
    *   `salt` (`bytes`): A cryptographic salt for HKDF (should be unique per exchange). Must be at least `SALT_BYTES` long.
    *   `key_length` (`int`, optional): The desired length of the derived key in bytes. Defaults to `DERIVED_KEY_BYTES`. Must be at least `AES_KEY_BYTES + 16`.
*   **Returns:**
    *   `Tuple[bytes, bytes]`: A tuple containing:
        *   `derived_key` (`bytes`): The final shared key derived via HKDF.
        *   `kem_ciphertext` (`bytes`): The ciphertext generated by the KEM encapsulation, to be sent to the peer.
*   **Raises:**
    *   `TypeError`: If any input key or KEM instance has an invalid type.
    *   `ValueError`: If ECC keys use different curves, if KEM/ECC public keys or hashes are invalid/empty, if the salt is too short, or if the requested `key_length` is too small.
    *   `RuntimeError`: If ECDH key exchange results in an invalid secret or if KEM encapsulation fails.

### `derive_shared_key_from_kem_ciphertext(own_ecc_private_key, peer_ecc_public_key, own_kem_instance, received_kem_ciphertext, peer_public_key_hash, own_public_key_hash, salt, key_length=DERIVED_KEY_BYTES)`

Derives a shared secret key using a hybrid approach (ECDH + KEM decapsulation) and HKDF. This function is typically called by the party responding to the key exchange initiation, using the ciphertext received from the initiator.

*   **Args:**
    *   `own_ecc_private_key` (`ec.EllipticCurvePrivateKey`): The responder's ECC private key.
    *   `peer_ecc_public_key` (`ec.EllipticCurvePublicKey`): The initiator's ECC public key.
    *   `own_kem_instance` (`oqs.KeyEncapsulation`): The responder's KEM instance (containing their private key).
    *   `received_kem_ciphertext` (`bytes`): The KEM ciphertext received from the initiator.
    *   `peer_public_key_hash` (`str`): The hash of the initiator's public ECC key PEM.
    *   `own_public_key_hash` (`str`): The hash of the responder's public ECC key PEM.
    *   `salt` (`bytes`): The same cryptographic salt used by the initiator for HKDF. Must be at least `SALT_BYTES` long.
    *   `key_length` (`int`, optional): The desired length of the derived key in bytes. Defaults to `DERIVED_KEY_BYTES`. Must match the length used by the initiator and be at least `AES_KEY_BYTES + 16`.
*   **Returns:**
    *   `bytes`: The final shared key derived via HKDF. Should match the key derived by the initiator.
*   **Raises:**
    *   `TypeError`: If any input key or KEM instance has an invalid type.
    *   `ValueError`: If ECC keys use different curves, if KEM ciphertext or public key hashes are invalid/empty, if the salt is too short, or if the requested `key_length` is too small.
    *   `RuntimeError`: If ECDH key exchange results in an invalid secret or if KEM decapsulation fails.

### `aes_gcm_hmac_encrypt(key, data, associated_data=b"")`

Encrypts data using AES-GCM and authenticates the ciphertext, nonce, and associated data using HMAC-SHA3-512. Assumes the input `key` is derived via HKDF and contains both the AES and HMAC keys.

*   **Args:**
    *   `key` (`bytes`): The combined AES and HMAC key (must be `DERIVED_KEY_BYTES` long). The first `AES_KEY_BYTES` are used for AES, the rest for HMAC.
    *   `data` (`bytes`): The plaintext data to encrypt.
    *   `associated_data` (`bytes`, optional): Additional data to authenticate but not encrypt. Defaults to an empty byte string.
*   **Returns:**
    *   `bytes`: The encrypted bundle, consisting of `nonce || ciphertext || hmac_tag`.
*   **Raises:**
    *   `ValueError`: If the input `key` has an incorrect length.
    *   `RuntimeError`: If AES-GCM encryption or HMAC calculation fails.

### `aes_gcm_hmac_decrypt(key, encrypted_bundle, associated_data=b"")`

Decrypts data previously encrypted with `aes_gcm_hmac_encrypt`. It first verifies the HMAC tag and then decrypts using AES-GCM.

*   **Args:**
    *   `key` (`bytes`): The combined AES and HMAC key (must be `DERIVED_KEY_BYTES` long).
    *   `encrypted_bundle` (`bytes`): The output from `aes_gcm_hmac_encrypt` (`nonce || ciphertext || hmac_tag`).
    *   `associated_data` (`bytes`, optional): The same associated data used during encryption. Defaults to an empty byte string.
*   **Returns:**
    *   `bytes`: The original plaintext data.
*   **Raises:**
    *   `ValueError`: If the input `key` has an incorrect length or if `encrypted_bundle` is too short.
    *   `cryptography.exceptions.InvalidSignature`: If the HMAC verification fails or if the AES-GCM decryption authentication check fails.
    *   `RuntimeError`: If HMAC verification or AES-GCM decryption encounters an unexpected error.

### `sign_data(data, private_key)`

Signs arbitrary data using the provided ECC private key with ECDSA and the predefined hash algorithm (`HASH_ALGORITHM`).

*   **Args:**
    *   `data` (`bytes`): The data to sign.
    *   `private_key` (`ec.EllipticCurvePrivateKey`): The ECC private key to use for signing.
*   **Returns:**
    *   `bytes`: The ECDSA signature.
*   **Raises:**
    *   `TypeError`: If `private_key` is not a valid `EllipticCurvePrivateKey`.
    *   `RuntimeError`: If the signing process fails.

### `verify_signature(data, signature, public_key)`

Verifies an ECDSA signature against the original data and the corresponding ECC public key.

*   **Args:**
    *   `data` (`bytes`): The original data that was signed.
    *   `signature` (`bytes`): The ECDSA signature to verify.
    *   `public_key` (`ec.EllipticCurvePublicKey`): The ECC public key corresponding to the private key used for signing.
*   **Returns:**
    *   `bool`: `True` if the signature is valid, `False` otherwise.
*   **Raises:**
    *   `TypeError`: If `public_key` is not a valid `EllipticCurvePublicKey`. (Note: `InvalidSignature` exceptions during verification result in `False` being returned, not raised).

### `derive_key_from_password(password, salt, time_cost=ARGON2_DEFAULT_TIME_COST, memory_cost=ARGON2_DEFAULT_MEMORY_COST, parallelism=ARGON2_DEFAULT_PARALLELISM, key_length=ARGON2_DEFAULT_HASH_LEN)`

Derives a cryptographic key from a user-provided password using the Argon2id algorithm.

*   **Args:**
    *   `password` (`str`): The password to derive the key from (must be at least 8 characters).
    *   `salt` (`bytes`): A unique salt for this password hash (must be at least `SALT_BYTES` long).
    *   `time_cost` (`int`, optional): Argon2 time cost parameter. Defaults to `ARGON2_DEFAULT_TIME_COST`. Must be >= 1.
    *   `memory_cost` (`int`, optional): Argon2 memory cost parameter (in KiB). Defaults to `ARGON2_DEFAULT_MEMORY_COST`. Must be >= 8.
    *   `parallelism` (`int`, optional): Argon2 parallelism parameter. Defaults to `ARGON2_DEFAULT_PARALLELISM`. Must be >= 1.
    *   `key_length` (`int`, optional): The desired length of the derived key in bytes. Defaults to `ARGON2_DEFAULT_HASH_LEN`. Must be >= 16.
*   **Returns:**
    *   `bytes`: The derived key.
*   **Raises:**
    *   `ValueError`: If the password is too short, the salt is too short, or any Argon2 parameter is invalid.
    *   `argon2.exceptions.HashingError`: If the Argon2 hashing process fails internally.
    *   `RuntimeError`: For other unexpected errors during key derivation.

## Example Usage (`if __name__ == "__main__":`)

The script includes a self-contained example demonstrating the core functionalities:
1.  Generation of ECC and KEM key pairs for two parties (Alice and Bob).
2.  Hybrid key exchange initiated by Alice, resulting in a shared key derived by both parties.
3.  Assertion to verify both parties derived the same key.
4.  Encryption of a message by Alice using the shared key and `aes_gcm_hmac_encrypt`.
5.  Decryption of the message by Bob using the shared key and `aes_gcm_hmac_decrypt`.
6.  Assertion to verify the decrypted message matches the original.
7.  Signing of the message by Alice using her ECC private key.
8.  Verification of the signature by Bob using Alice's ECC public key.
9.  Assertion to verify the signature is valid.
10. Derivation of a key from a password using `derive_key_from_password`.
11. Prints success messages for each stage or raises an error if any step fails.
12. Includes a `finally` block to ensure KEM resources (`kem_instance.free()`) are released.

---

# Module: `aivantguard-common/utility/logger.py`

This module provides a configurable logging setup using Python's standard `logging` module. It features timezone-aware timestamps with millisecond precision and allows configuration via environment variables.

## Configuration (via Environment Variables)

*   `LOG_LEVEL` (Default: `"INFO"`): Sets the minimum logging level (e.g., "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
*   `LOG_TIMEZONE` (Default: `"Europe/Madrid"`): Sets the timezone for log timestamps (e.g., "UTC", "America/New_York"). Uses `zoneinfo` library. Falls back to UTC if the specified timezone is not found.

## Constants

*   `LOG_FORMAT`: `"%(asctime)s [%(levelname)s] [%(module)s] - %(message)s"` - The format string for log messages.
*   `LOG_DATE_FORMAT`: `"%Y.%m.%d %H:%M:%S.%f"` - The format string for timestamps, including milliseconds (`%f`).

## Classes

### `TzFormatter(logging.Formatter)`

A custom logging formatter that ensures timestamps are in the configured timezone and handles millisecond formatting correctly.

*   **Purpose:** Overrides the default `formatTime` method to convert log record timestamps to the specified timezone (`tz`) and format them according to the `datefmt`, correctly substituting milliseconds using `record.msecs`.
*   **Initialization:**
    *   `__init__(self, fmt=None, datefmt=None, tz=None, style='%', validate=True)`: Initializes the formatter, storing the target timezone `tz`.
*   **Methods:**
    *   `formatTime(self, record, datefmt=None)`: Converts `record.created` (Unix timestamp) to a `datetime` object in the target timezone `self.tz`. Formats the `datetime` object using `datefmt`. If `datefmt` contains `%f`, it formats the main part and appends milliseconds manually for precision. If `datefmt` is not provided, it defaults to an ISO 8601 format.

## Functions

### `setup_logger(name="app_logger", level=None)`

Configures and returns a logger instance.

*   **Args:**
    *   `name` (`str`, optional): The name for the logger. Defaults to `"app_logger"`. Using `__name__` is common practice when called from other modules.
    *   `level` (`int` | `str`, optional): The logging threshold level. If `None`, reads from the `LOG_LEVEL` environment variable (defaulting to `INFO`). Accepts standard logging level integers (e.g., `logging.DEBUG`) or case-insensitive level names (e.g., `"DEBUG"`).
*   **Returns:**
    *   `logging.Logger`: The configured logger instance.
*   **Behavior:**
    1.  Determines the logging level based on the `level` argument or environment variables.
    2.  Gets the logger instance using `logging.getLogger(name)`.
    3.  Sets the logger's level.
    4.  Clears existing handlers to prevent duplication if called multiple times for the same logger name.
    5.  Creates a `logging.StreamHandler` to output logs to `sys.stdout`.
    6.  Creates an instance of `TzFormatter` with the configured `LOG_FORMAT`, `LOG_DATE_FORMAT`, and timezone (`_tz`).
    7.  Sets the formatter on the handler.
    8.  Adds the handler to the logger.
    9.  Returns the configured logger.

## Global Instance

*   `logger`: A pre-configured `logging.Logger` instance created by calling `setup_logger()` when the module is imported. This provides a ready-to-use logger with the default settings.

## Example Usage (from comments in the code)

To use the configured logger in other modules:

```python
import logging

# Get the logger instance configured by this module
logger = logging.getLogger("app_logger")
# Or, if setting up logging centrally, potentially use:
# logger = logging.getLogger(__name__) # If setup_logger was called elsewhere

# Log messages at different levels
logger.debug("Detailed information for developers.") # Only shown if level is DEBUG
logger.info("Standard operational message.")
logger.warning("Potential issue detected.")
logger.error("An error occurred that prevented normal operation.")
logger.critical("A critical error occurred, application may crash.")

# Log exceptions with stack traces
try:
    result = 1 / 0
except ZeroDivisionError:
    logger.exception("An unexpected error happened during division.")
```