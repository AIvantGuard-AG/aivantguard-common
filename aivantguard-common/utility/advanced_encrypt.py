# aivantguard-common/utility/advanced_encrypt.py

import hashlib
import secrets
from typing import Tuple, NamedTuple

# Third-party libraries
import oqs
from argon2 import Type as Argon2Type
from argon2.exceptions import HashingError
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# --- Constants ---
EC_CURVE = ec.SECP521R1()
ECC_KEY_SIZE_BYTES = (EC_CURVE.key_size + 7) // 8
HASH_ALGORITHM = hashes.SHA3_512
KEM_ALGORITHM = "Kyber1024"
HKDF_INFO_PREFIX = b"HybridKeyDerivation_v1_"
AES_KEY_BYTES = 32
HMAC_KEY_BYTES = 32
DERIVED_KEY_BYTES = AES_KEY_BYTES + HMAC_KEY_BYTES
SALT_BYTES = 16
AES_NONCE_BYTES = 12
HMAC_TAG_BYTES = HASH_ALGORITHM.digest_size

# Argon2 parameters
ARGON2_DEFAULT_TIME_COST = 3
ARGON2_DEFAULT_MEMORY_COST = 65536  # KiB
ARGON2_DEFAULT_PARALLELISM = 4
ARGON2_DEFAULT_HASH_LEN = 32
ARGON2_TYPE = Argon2Type.ID

_BACKEND = default_backend()


# --- Data Structures ---
class EccKeyPair(NamedTuple):
    """Represents an ECC key pair."""
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    private_pem: bytes
    public_pem: bytes
    public_hash: str


class KemKeyPair(NamedTuple):
    """Represents a KEM key pair."""
    kem_instance: oqs.KeyEncapsulation
    public_key: bytes


# --- Core Functions ---
def generate_ecc_keypair() -> EccKeyPair:
    """Generates an ECC key pair using the predefined curve."""
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
    if not isinstance(EC_CURVE, EllipticCurve):
        raise ValueError("Invalid EC curve configuration")
    private_key = ec.generate_private_key(EC_CURVE, _BACKEND)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_hash = get_hash(public_pem)
    return EccKeyPair(private_key, public_key, private_pem, public_pem, public_hash)


def generate_kem_keypair() -> KemKeyPair:
    """Generates a KEM key pair using the predefined algorithm."""
    if not isinstance(KEM_ALGORITHM, str):
        raise ValueError("Invalid KEM algorithm configuration")
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
    try:
        public_key = kem.generate_keypair()
        return KemKeyPair(kem, public_key)
    except Exception as ex:
        kem.free()
        raise RuntimeError(f"KEM key pair generation failed: {ex}") from e


def generate_salt(length: int = SALT_BYTES) -> bytes:
    """Generates a cryptographically secure random salt."""
    if length < 16:
        raise ValueError("Salt length must be at least 16 bytes")
    return secrets.token_bytes(length)


def get_hash(data_for_hash: bytes) -> str:
    """Computes the SHA3-512 hash of the input data."""
    if not isinstance(data_for_hash, bytes):
        raise TypeError("Input must be bytes")
    hash_object = hashlib.sha3_512()
    hash_object.update(data_for_hash)
    return hash_object.hexdigest()


def derive_shared_key(
        own_ecc_private_key: ec.EllipticCurvePrivateKey,
        peer_ecc_public_key: ec.EllipticCurvePublicKey,
        own_kem_instance: oqs.KeyEncapsulation,
        peer_kem_public_key: bytes,
        peer_public_key_hash: str,
        own_public_key_hash: str,
        salt: bytes,
        key_length: int = DERIVED_KEY_BYTES
) -> Tuple[bytes, bytes]:
    if not isinstance(own_ecc_private_key, ec.EllipticCurvePrivateKey) or \
            not isinstance(peer_ecc_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Invalid ECC key types provided.")
    if own_ecc_private_key.curve.name != EC_CURVE.name or \
            peer_ecc_public_key.curve.name != EC_CURVE.name:
        raise ValueError(f"Both ECC keys must use the same curve ({EC_CURVE.name})")
    if not isinstance(own_kem_instance, oqs.KeyEncapsulation):
        raise TypeError("Invalid KEM instance provided.")
    if not isinstance(peer_kem_public_key, bytes) or not peer_kem_public_key:
        raise ValueError("Peer KEM public key must be non-empty bytes.")
    if not isinstance(peer_public_key_hash, str) or not peer_public_key_hash:
        raise ValueError("Peer public key hash must be a non-empty string.")
    if not isinstance(own_public_key_hash, str) or not own_public_key_hash:
        raise ValueError("Own public key hash must be a non-empty string.")
    if not isinstance(salt, bytes) or len(salt) < SALT_BYTES:
        raise ValueError(f"Salt must be bytes and at least {SALT_BYTES} long.")
    if key_length < AES_KEY_BYTES + 16:
        raise ValueError(f"Key length must be at least {AES_KEY_BYTES + 16} bytes.")

    ecdh_secret = own_ecc_private_key.exchange(ec.ECDH(), peer_ecc_public_key)
    if not ecdh_secret or ecdh_secret == b'\x00' * len(ecdh_secret):
        raise RuntimeError("ECDH resulted in an invalid or weak secret.")

    kem_ciphertext, kem_secret = own_kem_instance.encap_secret(peer_kem_public_key)
    if not kem_secret:
        raise RuntimeError("KEM encapsulation failed to produce a secret.")

    combined_secret = ecdh_secret + kem_secret
    _hashes = sorted([own_public_key_hash, peer_public_key_hash])
    info = HKDF_INFO_PREFIX + "".join(_hashes).encode('utf-8')
    hkdf_instance = HKDF(
        algorithm=HASH_ALGORITHM(),
        length=key_length,
        salt=salt,
        info=info,
        backend=_BACKEND
    )
    derived_key = hkdf_instance.derive(combined_secret)
    return derived_key, kem_ciphertext


def derive_shared_key_from_kem_ciphertext(
        own_ecc_private_key: ec.EllipticCurvePrivateKey,
        peer_ecc_public_key: ec.EllipticCurvePublicKey,
        own_kem_instance: oqs.KeyEncapsulation,
        received_kem_ciphertext: bytes,
        peer_public_key_hash: str,
        own_public_key_hash: str,
        salt: bytes,
        key_length: int = DERIVED_KEY_BYTES
) -> bytes:
    if not isinstance(own_ecc_private_key, ec.EllipticCurvePrivateKey) or \
            not isinstance(peer_ecc_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Invalid ECC key types provided.")
    if own_ecc_private_key.curve.name != EC_CURVE.name or \
            peer_ecc_public_key.curve.name != EC_CURVE.name:
        raise ValueError(f"Both ECC keys must use the same curve ({EC_CURVE.name})")
    if not isinstance(own_kem_instance, oqs.KeyEncapsulation):
        raise TypeError("Invalid KEM instance provided.")
    if not isinstance(received_kem_ciphertext, bytes) or not received_kem_ciphertext:
        raise ValueError("Received KEM ciphertext must be non-empty bytes.")
    if not isinstance(peer_public_key_hash, str) or not peer_public_key_hash:
        raise ValueError("Peer public key hash must be a non-empty string.")
    if not isinstance(own_public_key_hash, str) or not own_public_key_hash:
        raise ValueError("Own public key hash must be a non-empty string.")
    if not isinstance(salt, bytes) or len(salt) < SALT_BYTES:
        raise ValueError(f"Salt must be bytes and at least {SALT_BYTES} long.")
    if key_length < AES_KEY_BYTES + 16:
        raise ValueError(f"Key length must be at least {AES_KEY_BYTES + 16} bytes.")

    ecdh_secret = own_ecc_private_key.exchange(ec.ECDH(), peer_ecc_public_key)
    if not ecdh_secret or ecdh_secret == b'\x00' * len(ecdh_secret):
        raise RuntimeError("ECDH resulted in an invalid or weak secret.")

    kem_secret = own_kem_instance.decap_secret(received_kem_ciphertext)
    if not kem_secret:
        raise RuntimeError("KEM decapsulation failed to produce a secret.")

    combined_secret = ecdh_secret + kem_secret
    _hashes = sorted([own_public_key_hash, peer_public_key_hash])
    info = HKDF_INFO_PREFIX + "".join(_hashes).encode('utf-8')
    hkdf_instance = HKDF(
        algorithm=HASH_ALGORITHM(),
        length=key_length,
        salt=salt,
        info=info,
        backend=_BACKEND
    )
    return hkdf_instance.derive(combined_secret)


def aes_gcm_hmac_encrypt(key: bytes, data: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypts data using AES-GCM and adds an HMAC-SHA3-512 tag."""
    if len(key) != DERIVED_KEY_BYTES:
        raise ValueError(f"Key must be exactly {DERIVED_KEY_BYTES} bytes long.")

    aes_key = key[:AES_KEY_BYTES]
    hmac_key = key[AES_KEY_BYTES:]
    nonce = secrets.token_bytes(AES_NONCE_BYTES)

    try:
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    except Exception as ex:
        raise RuntimeError(f"AES-GCM encryption failed: {ex}") from ex

    try:
        h = hmac.HMAC(hmac_key, HASH_ALGORITHM(), backend=_BACKEND)
        h.update(nonce + ciphertext + associated_data)
        hmac_tag = h.finalize()
    except Exception as ex:
        raise RuntimeError(f"HMAC calculation failed: {ex}") from ex

    return nonce + ciphertext + hmac_tag


def aes_gcm_hmac_decrypt(key: bytes, encrypted_bundle: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypts data encrypted with aes_gcm_hmac_encrypt."""
    if len(key) != DERIVED_KEY_BYTES:
        raise ValueError(f"Key must be exactly {DERIVED_KEY_BYTES} bytes long.")
    if len(encrypted_bundle) < AES_NONCE_BYTES + HMAC_TAG_BYTES:
        raise ValueError("Encrypted data bundle is too short to be valid.")

    aes_key = key[:AES_KEY_BYTES]
    hmac_key = key[AES_KEY_BYTES:]

    nonce = encrypted_bundle[:AES_NONCE_BYTES]
    hmac_tag = encrypted_bundle[-HMAC_TAG_BYTES:]
    ciphertext = encrypted_bundle[AES_NONCE_BYTES:-HMAC_TAG_BYTES]

    try:
        h = hmac.HMAC(hmac_key, HASH_ALGORITHM(), backend=_BACKEND)
        h.update(nonce + ciphertext + associated_data)
        h.verify(hmac_tag)
    except InvalidSignature:
        raise InvalidSignature("HMAC verification failed.")
    except Exception as ex:
        raise RuntimeError(f"HMAC verification encountered an error: {ex}") from ex

    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except InvalidSignature:
        raise InvalidSignature("AES-GCM decryption failed authentication check.")
    except Exception as ex:
        raise RuntimeError(f"AES-GCM decryption failed: {ex}") from ex


def sign_data(data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Signs data using ECDSA with SHA3-512."""
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Invalid private key type provided.")
    try:
        signature = private_key.sign(
            data=data,
            signature_algorithm=ec.ECDSA(HASH_ALGORITHM())
        )
        return signature
    except Exception as ex:
        raise RuntimeError(f"Data signing failed: {ex}") from ex


def verify_signature(data: bytes, signature: bytes, public_key: ec.EllipticCurvePublicKey) -> bool:
    """Verifies an ECDSA SHA3-512 signature."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Invalid public key type provided.")
    try:
        public_key.verify(
            signature=signature,
            data=data,
            signature_algorithm=ec.ECDSA(HASH_ALGORITHM())
        )
        return True
    except InvalidSignature:
        return False
    except Exception as ex:
        print(f"Warning: Signature verification encountered an error: {ex}")
        return False


def derive_key_from_password(
        password: str,
        salt: bytes,
        time_cost: int = ARGON2_DEFAULT_TIME_COST,
        memory_cost: int = ARGON2_DEFAULT_MEMORY_COST,
        parallelism: int = ARGON2_DEFAULT_PARALLELISM,
        key_length: int = ARGON2_DEFAULT_HASH_LEN
) -> bytes:
    """Derives a key from a password using Argon2id."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not isinstance(salt, bytes) or len(salt) < SALT_BYTES:
        raise ValueError(f"Salt must be bytes and at least {SALT_BYTES} long.")
    if time_cost < 1 or memory_cost < 8 or parallelism < 1 or key_length < 16:
        raise ValueError("Invalid Argon2 parameter values provided.")

    try:
        key = hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            type=ARGON2_TYPE
        )
        return key
    except HashingError as ex:
        raise HashingError(f"Argon2 key derivation failed: {str(ex)}") from ex
    except Exception as ex:
        raise RuntimeError(f"Unexpected error during key derivation: {ex}") from ex


# --- Example Usage ---
if __name__ == "__main__":
    alice_kem = None
    bob_kem = None
    try:
        # Key generation
        alice_ecc = generate_ecc_keypair()
        alice_kem = generate_kem_keypair()
        bob_ecc = generate_ecc_keypair()
        bob_kem = generate_kem_keypair()

        # Key exchange
        msg_salt = generate_salt()
        alice_shared_key, kem_ciphertext_for_bob = derive_shared_key(
            alice_ecc.private_key,
            bob_ecc.public_key,
            alice_kem.kem_instance,
            bob_kem.public_key,
            bob_ecc.public_hash,
            alice_ecc.public_hash,
            msg_salt
        )
        bob_shared_key = derive_shared_key_from_kem_ciphertext(
            bob_ecc.private_key,
            alice_ecc.public_key,
            bob_kem.kem_instance,
            kem_ciphertext_for_bob,
            alice_ecc.public_hash,
            bob_ecc.public_hash,
            msg_salt
        )

        assert alice_shared_key == bob_shared_key, "Key derivation failed"
        print("Key derivation successful")

        # Encryption
        message = b"Hybrid PQC test message"
        metadata = b"test_context"
        encrypted_data = aes_gcm_hmac_encrypt(alice_shared_key, message, metadata)
        decrypted_data = aes_gcm_hmac_decrypt(bob_shared_key, encrypted_data, metadata)

        assert message == decrypted_data, "Encryption/decryption failed"
        print("Encryption/decryption successful")

        # Signing
        _signature = sign_data(message, alice_ecc.private_key)
        assert verify_signature(message, _signature, alice_ecc.public_key), "Signature verification failed"
        print("Signature verification successful")

        # Password derivation
        password_derived_key = derive_key_from_password("strongpassword123", generate_salt())
        print("Password derivation successful")

        print("All cryptographic operations completed successfully")

    except Exception as e:
        print(f"Error in example usage: {e}")
        raise

    finally:
        if 'alice_kem' in locals() and alice_kem:
            alice_kem.kem_instance.free()
        if 'bob_kem' in locals() and bob_kem:
            bob_kem.kem_instance.free()
