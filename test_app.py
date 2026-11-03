"""Focused correctness tests for the cryptographic benchmark helpers."""

import secrets
import unittest

import app
from cryptography.exceptions import InvalidTag


class BenchmarkCryptoTests(unittest.TestCase):
    def test_rsa_key_transport_and_aes_round_trip(self):
        aes_key = app.establish_aes_key("RSA-2048")
        self.assertEqual(len(aes_key), 32)
        self.assert_all_payload_sizes_round_trip(aes_key)

    def test_x25519_exchange_and_aes_round_trip(self):
        aes_key = app.establish_aes_key("X25519")
        self.assertEqual(len(aes_key), 32)
        self.assert_all_payload_sizes_round_trip(aes_key)

    def assert_all_payload_sizes_round_trip(self, aes_key):
        for data_size in app.SUPPORTED_DATA_SIZES.values():
            with self.subTest(data_size=data_size):
                plaintext = secrets.token_bytes(data_size)
                encrypted_file = app.encrypt_file_payload(plaintext, aes_key)
                self.assertEqual(
                    app.decrypt_file_payload(encrypted_file, aes_key), plaintext
                )
                (
                    encryption,
                    decryption,
                    encryption_memory,
                    decryption_memory,
                    ciphertext_size,
                ) = app.benchmark_aes(aes_key, plaintext, 2)
                self.assertGreaterEqual(encryption["average"], 0)
                self.assertGreaterEqual(decryption["average"], 0)
                self.assertGreaterEqual(encryption_memory, 0)
                self.assertGreaterEqual(decryption_memory, 0)
                self.assertEqual(ciphertext_size, data_size + 16)
                self.assertGreater(
                    app._throughput_mib_per_second(
                        data_size, encryption["average"]
                    ),
                    0,
                )

    def test_classical_key_size_reporting(self):
        for algorithm in ("RSA-2048", "X25519"):
            with self.subTest(algorithm=algorithm):
                sizes = app.benchmark_key_generation(algorithm, 1)
                self.assertGreater(sizes["public_size"], 0)
                self.assertGreater(sizes["private_size"], 0)

    @unittest.skipUnless(
        app.inspect_mlkem_support()[0],
        "ML-KEM-768 and its native liboqs library are not enabled",
    )
    def test_mlkem_encapsulation_and_aes_round_trip(self):
        available, details, error = app.inspect_mlkem_support()
        self.assertTrue(available, error)
        aes_key = app.establish_aes_key("ML-KEM-768", details)
        self.assertEqual(len(aes_key), 32)
        self.assert_all_payload_sizes_round_trip(aes_key)

    def test_file_envelope_rejects_tampering_and_wrong_keys(self):
        key = secrets.token_bytes(32)
        encrypted_file = app.encrypt_file_payload(b"private data", key)
        with self.assertRaises(InvalidTag):
            app.decrypt_file_payload(encrypted_file + b"tampered", key)
        with self.assertRaises(InvalidTag):
            app.decrypt_file_payload(encrypted_file, secrets.token_bytes(32))
        with self.assertRaises(ValueError):
            app.decrypt_file_payload(b"not an encrypted file", key)


if __name__ == "__main__":
    unittest.main()
