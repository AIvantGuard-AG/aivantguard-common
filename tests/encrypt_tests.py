import unittest
from aivantguard_common.utility import advanced_encrypt


class EncryptTests(unittest.TestCase):

    def test_key_encrypt_decrypt(self):
        alice_kem = None
        bob_kem = None
        try:
            # Key generation
            alice_ecc = advanced_encrypt.generate_ecc_keypair()
            alice_kem = advanced_encrypt.generate_kem_keypair()
            bob_ecc = advanced_encrypt.generate_ecc_keypair()
            bob_kem = advanced_encrypt.generate_kem_keypair()

            # Key exchange
            msg_salt = advanced_encrypt.generate_salt()
            alice_shared_key, kem_ciphertext_for_bob = advanced_encrypt.derive_shared_key(
                alice_ecc.private_key,
                bob_ecc.public_key,
                alice_kem.kem_instance,
                bob_kem.public_key,
                bob_ecc.public_hash,
                alice_ecc.public_hash,
                msg_salt
            )
            bob_shared_key = advanced_encrypt.derive_shared_key_from_kem_ciphertext(
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
            encrypted_data = advanced_encrypt.aes_gcm_hmac_encrypt(alice_shared_key, message, metadata)
            decrypted_data = advanced_encrypt.aes_gcm_hmac_decrypt(bob_shared_key, encrypted_data, metadata)

            assert message == decrypted_data, "Encryption/decryption failed"
            print("Encryption/decryption successful")

            # Signing
            _signature = advanced_encrypt.sign_data(message, alice_ecc.private_key)
            assert advanced_encrypt.verify_signature(message, _signature, alice_ecc.public_key), "Signature verification failed"
            print("Signature verification successful")

            # Password derivation
            password_derived_key = advanced_encrypt.derive_key_from_password("strongpassword123", advanced_encrypt.generate_salt())
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

    def test_password_encrypt_decrypt(self):
        _to_encrypt = b"The secret message."
        print("source text:", _to_encrypt)
        _salt = advanced_encrypt.generate_salt(64)
        _password = "TheReallySecretPassword"
        _aeskey = advanced_encrypt.derive_key_from_password(_password, _salt, key_length=advanced_encrypt.DERIVED_KEY_BYTES)
        _cipher = advanced_encrypt.aes_gcm_hmac_encrypt(_aeskey, _to_encrypt)
        print("Cipher text:", _cipher)
        _decripted_cipher = advanced_encrypt.aes_gcm_hmac_decrypt(_aeskey, _cipher)
        print("Decrypted text:", _decripted_cipher)
        assert _to_encrypt == _decripted_cipher, "Encryption/decryption failed"
        print("Password based encryption/decryption successful")


if __name__ == '__main__':
    unittest.main()
