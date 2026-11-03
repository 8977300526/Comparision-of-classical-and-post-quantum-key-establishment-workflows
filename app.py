"""Compare classical and post-quantum key-establishment workflows."""

from __future__ import annotations

import secrets
import statistics
import time
import tracemalloc
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.exceptions import InvalidTag

try:
    import oqs

    OQS_IMPORT_ERROR: Optional[str] = None
except (ImportError, OSError) as error:
    oqs = None
    OQS_IMPORT_ERROR = str(error)


ALGORITHM_NAMES = ("RSA-2048", "X25519", "ML-KEM-768")
SUPPORTED_DATA_SIZES = {
    "1 KB": 1024,
    "10 KB": 10 * 1024,
    "100 KB": 100 * 1024,
    "1 MB": 1024 * 1024,
}
MLKEM_NAME = "ML-KEM-768"
FILE_ENVELOPE_MAGIC = b"PQCF1"
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024

TIME_METRICS = {
    "key_generation": "Average Key Generation Time (ms)",
    "establishment": "Average Key Establishment/Transport Time (ms)",
    "encryption": "Average AES Encryption Time (ms)",
    "decryption": "Average AES Decryption Time (ms)",
}


def inspect_mlkem_support() -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """Check that both the Python wrapper and native ML-KEM implementation work."""
    if oqs is None:
        return (
            False,
            None,
            " ",
        )

    try:
        enabled_mechanisms = oqs.get_enabled_kem_mechanisms()
        if MLKEM_NAME not in enabled_mechanisms:
            return (
                False,
                None,
                "The native liboqs library loaded, but ML-KEM-768 is not enabled "
                "in this build.",
            )
        details = oqs.get_kem_details(MLKEM_NAME)
        required_fields = (
            "length_public_key",
            "length_secret_key",
            "length_ciphertext",
        )
        if any(field not in details for field in required_fields):
            return (
                False,
                None,
                "The installed liboqs-python version did not provide the ML-KEM "
                "size metadata required by this application.",
            )
        return True, details, ""
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        return (
            False,
            None,
            f"ML-KEM-768 could not be initialized: {error}",
        )


def _key_generation_sizes(
    algorithm: str, private_key: Any, public_key: Any, mlkem_details: Optional[Dict[str, Any]]
) -> Tuple[int, int]:
    """Return serialized public/private key sizes without displaying key material."""
    if algorithm == "RSA-2048":
        public_bytes = public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        private_bytes = private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )
        return len(public_bytes), len(private_bytes)

    if algorithm == "X25519":
        public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        private_bytes = private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        return len(public_bytes), len(private_bytes)

    if algorithm == MLKEM_NAME and mlkem_details is not None:
        public_size = int(mlkem_details["length_public_key"])
        private_size = int(mlkem_details["length_secret_key"])
        if len(public_key) != public_size:
            raise ValueError(
                "ML-KEM-768 public-key size does not match liboqs metadata."
            )
        return public_size, private_size

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def _timing_summary(samples_seconds: Sequence[float]) -> Dict[str, float]:
    """Summarize perf_counter readings in milliseconds."""
    samples_ms = [sample * 1000 for sample in samples_seconds]
    return {
        "average": statistics.mean(samples_ms),
        "minimum": min(samples_ms),
        "maximum": max(samples_ms),
        "std_dev": statistics.stdev(samples_ms) if len(samples_ms) > 1 else 0.0,
    }


def _measure_python_peak_memory(operation: Callable[[], Any]) -> int:
    """Measure traced Python allocation peak; native-library memory is not included."""
    tracing_was_active = tracemalloc.is_tracing()
    if not tracing_was_active:
        tracemalloc.start()
    baseline, _ = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    try:
        operation()
        _, peak = tracemalloc.get_traced_memory()
        return max(0, peak - baseline)
    finally:
        if not tracing_was_active:
            tracemalloc.stop()


def _throughput_mib_per_second(data_size: int, average_ms: float) -> float:
    """Calculate payload throughput in MiB/s from measured average latency."""
    if average_ms <= 0:
        return 0.0
    return (data_size / (1024 * 1024)) / (average_ms / 1000)


def encrypt_file_payload(plaintext: bytes, aes_key: bytes) -> bytes:
    """Create a versioned authenticated encrypted-file envelope in memory."""
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(
        nonce, plaintext, FILE_ENVELOPE_MAGIC
    )
    return FILE_ENVELOPE_MAGIC + nonce + ciphertext


def decrypt_file_payload(encrypted_payload: bytes, aes_key: bytes) -> bytes:
    """Validate and decrypt an encrypted-file envelope in memory."""
    header_size = len(FILE_ENVELOPE_MAGIC) + 12
    if len(encrypted_payload) < header_size + 16:
        raise ValueError("Encrypted file is truncated or has an invalid format.")
    if not encrypted_payload.startswith(FILE_ENVELOPE_MAGIC):
        raise ValueError("Encrypted file format is not supported.")

    nonce_start = len(FILE_ENVELOPE_MAGIC)
    nonce = encrypted_payload[nonce_start:header_size]
    ciphertext = encrypted_payload[header_size:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, FILE_ENVELOPE_MAGIC)


def benchmark_key_generation(
    algorithm: str, repetitions: int, mlkem_details: Optional[Dict[str, Any]] = None
) -> Dict[str, float]:
    """Measure key-pair generation and report serialized key sizes."""
    if repetitions < 1:
        raise ValueError("Repetitions must be at least 1.")

    samples: List[float] = []
    public_size = 0
    private_size = 0

    if algorithm == "RSA-2048":
        for _ in range(repetitions):
            started = time.perf_counter()
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            samples.append(time.perf_counter() - started)
            public_size, private_size = _key_generation_sizes(
                algorithm, private_key, private_key.public_key(), None
            )
    elif algorithm == "X25519":
        for _ in range(repetitions):
            started = time.perf_counter()
            private_key = x25519.X25519PrivateKey.generate()
            samples.append(time.perf_counter() - started)
            public_size, private_size = _key_generation_sizes(
                algorithm, private_key, private_key.public_key(), None
            )
    elif algorithm == MLKEM_NAME:
        if oqs is None or mlkem_details is None:
            raise RuntimeError("ML-KEM-768 is unavailable in the current environment.")
        with oqs.KeyEncapsulation(MLKEM_NAME) as kem:
            for _ in range(repetitions):
                started = time.perf_counter()
                public_key = kem.generate_keypair()
                samples.append(time.perf_counter() - started)
                public_size, private_size = _key_generation_sizes(
                    algorithm, None, public_key, mlkem_details
                )
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    summary = _timing_summary(samples)
    summary["public_size"] = float(public_size)
    summary["private_size"] = float(private_size)
    return summary


def benchmark_key_establishment(
    algorithm: str, repetitions: int, mlkem_details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Measure transport/agreement work; persistent recipient keys are pre-generated."""
    if repetitions < 1:
        raise ValueError("Repetitions must be at least 1.")

    samples: List[float] = []
    ciphertext_size: Optional[int] = None

    if algorithm == "RSA-2048":
        recipient_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        recipient_public = recipient_private.public_key()
        for _ in range(repetitions):
            started = time.perf_counter()
            session_key = secrets.token_bytes(32)
            wrapped_key = recipient_public.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            ciphertext_size = len(wrapped_key)
            received_key = recipient_private.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            if received_key != session_key:
                raise ValueError("RSA-OAEP key transport did not recover the sent key.")
            samples.append(time.perf_counter() - started)
    elif algorithm == "X25519":
        for _ in range(repetitions):
            started = time.perf_counter()
            alice_private = x25519.X25519PrivateKey.generate()
            bob_private = x25519.X25519PrivateKey.generate()
            alice_secret = alice_private.exchange(bob_private.public_key())
            bob_secret = bob_private.exchange(alice_private.public_key())
            if alice_secret != bob_secret:
                raise ValueError("X25519 parties derived different shared secrets.")
            samples.append(time.perf_counter() - started)
    elif algorithm == MLKEM_NAME:
        if oqs is None or mlkem_details is None:
            raise RuntimeError("ML-KEM-768 is unavailable in the current environment.")
        with oqs.KeyEncapsulation(MLKEM_NAME) as kem:
            recipient_public = kem.generate_keypair()
            for _ in range(repetitions):
                started = time.perf_counter()
                ciphertext, sender_secret = kem.encap_secret(recipient_public)
                receiver_secret = kem.decap_secret(ciphertext)
                if len(ciphertext) != int(mlkem_details["length_ciphertext"]):
                    raise ValueError(
                        "ML-KEM-768 ciphertext size does not match liboqs metadata."
                    )
                if sender_secret != receiver_secret:
                    raise ValueError("ML-KEM-768 parties derived different secrets.")
                ciphertext_size = len(ciphertext)
                samples.append(time.perf_counter() - started)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    summary: Dict[str, Any] = _timing_summary(samples)
    summary["ciphertext_size"] = ciphertext_size
    return summary


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """Expand a key-agreement secret to the AES-256-GCM key length."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pqc-cloud-data-sharing-aes-256-gcm-v1",
    ).derive(shared_secret)


def establish_aes_key(
    algorithm: str, mlkem_details: Optional[Dict[str, Any]] = None
) -> bytes:
    """Run one real exchange/transport and return the receiver's AES key."""
    if algorithm == "RSA-2048":
        recipient_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        session_key = secrets.token_bytes(32)
        wrapped_key = recipient_private.public_key().encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        received_key = recipient_private.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        if received_key != session_key:
            raise ValueError("RSA-OAEP key transport verification failed.")
        return received_key

    if algorithm == "X25519":
        alice_private = x25519.X25519PrivateKey.generate()
        bob_private = x25519.X25519PrivateKey.generate()
        alice_secret = alice_private.exchange(bob_private.public_key())
        bob_secret = bob_private.exchange(alice_private.public_key())
        if alice_secret != bob_secret:
            raise ValueError("X25519 shared-secret verification failed.")
        return _derive_aes_key(alice_secret)

    if algorithm == MLKEM_NAME:
        if oqs is None or mlkem_details is None:
            raise RuntimeError("ML-KEM-768 is unavailable in the current environment.")
        with oqs.KeyEncapsulation(MLKEM_NAME) as kem:
            recipient_public = kem.generate_keypair()
            ciphertext, sender_secret = kem.encap_secret(recipient_public)
            receiver_secret = kem.decap_secret(ciphertext)
        if sender_secret != receiver_secret:
            raise ValueError("ML-KEM-768 shared-secret verification failed.")
        return _derive_aes_key(receiver_secret)

    raise ValueError(f"Unknown algorithm: {algorithm}")


def benchmark_aes(
    aes_key: bytes, plaintext: bytes, repetitions: int
) -> Tuple[Dict[str, float], Dict[str, float], int, int, int]:
    """Measure AES timings, throughput, and separately sampled Python memory peaks."""
    if repetitions < 1:
        raise ValueError("Repetitions must be at least 1.")

    cipher = AESGCM(aes_key)
    encryption_samples: List[float] = []
    decryption_samples: List[float] = []
    nonce_prefix = secrets.token_bytes(8)

    ciphertext = b""
    last_nonce = b""
    for iteration in range(repetitions):
        nonce = nonce_prefix + iteration.to_bytes(4, byteorder="big")
        started = time.perf_counter()
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        encryption_samples.append(time.perf_counter() - started)

        started = time.perf_counter()
        recovered = cipher.decrypt(nonce, ciphertext, None)
        decryption_samples.append(time.perf_counter() - started)

        if recovered != plaintext:
            raise ValueError("AES-256-GCM decryption did not match the input data.")

        last_nonce = nonce

    encryption_memory = _measure_python_peak_memory(
        lambda: cipher.encrypt(
            secrets.token_bytes(12), plaintext, None
        )
    )
    decryption_memory = _measure_python_peak_memory(
        lambda: cipher.decrypt(last_nonce, ciphertext, None)
    )
    return (
        _timing_summary(encryption_samples),
        _timing_summary(decryption_samples),
        encryption_memory,
        decryption_memory,
        len(ciphertext),
    )


def _algorithm_description(algorithm: str) -> Tuple[str, str]:
    """Return the algorithm category and the quantum-security explanation."""
    if algorithm == "RSA-2048":
        return (
            "Classical public-key key transport",
            "Not quantum-resistant: Shor's algorithm would break RSA factoring "
            "with a sufficiently capable cryptographically relevant quantum computer.",
        )
    if algorithm == "X25519":
        return (
            "Classical elliptic-curve key agreement",
            "Not quantum-resistant: Shor's algorithm would break the underlying "
            "elliptic-curve discrete-log problem.",
        )
    return (
        "Post-quantum key encapsulation",
        "Standardized by NIST as FIPS 203 and designed to resist known classical "
        "and quantum attacks; no cryptographic algorithm is guaranteed unbreakable.",
    )


def _empty_result_row(
    algorithm: str, data_size: int, status: str, error_text: str
) -> Dict[str, Any]:
    """Create an explicit unavailable/failed row rather than hiding a missing result."""
    algorithm_type, quantum_classification = _algorithm_description(algorithm)
    return {
        "Algorithm": algorithm,
        "Algorithm Type": algorithm_type,
        "Average Key Generation Time (ms)": None,
        "Minimum Key Generation Time (ms)": None,
        "Maximum Key Generation Time (ms)": None,
        "Key Generation Std Dev (ms)": None,
        "Average Key Establishment/Transport Time (ms)": None,
        "Minimum Key Establishment/Transport Time (ms)": None,
        "Maximum Key Establishment/Transport Time (ms)": None,
        "Key Establishment Std Dev (ms)": None,
        "Average AES Encryption Time (ms)": None,
        "Average AES Decryption Time (ms)": None,
        "AES-GCM Ciphertext Size (bytes)": None,
        "AES Encryption Throughput (MiB/s)": None,
        "AES Decryption Throughput (MiB/s)": None,
        "Peak Python Memory - AES Encryption (bytes)": None,
        "Peak Python Memory - AES Decryption (bytes)": None,
        "Public Key Size (bytes)": None,
        "Private Key Size (bytes)": None,
        "Encapsulation or Ciphertext Size (bytes)": None,
        "Test Data Size (bytes)": data_size,
        "Correctness Verification": "Not run",
        "Quantum Resistance Classification": quantum_classification,
        "Performance Score (0-100)": None,
        "Status": status,
        "Error": error_text,
    }


def _benchmark_one_algorithm(
    algorithm: str,
    repetitions: int,
    data_sizes: Sequence[int],
    mlkem_details: Optional[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Run key, exchange, and file-data measurements for one algorithm."""
    key_generation = benchmark_key_generation(
        algorithm, repetitions, mlkem_details
    )
    establishment = benchmark_key_establishment(
        algorithm, repetitions, mlkem_details
    )
    algorithm_type, quantum_classification = _algorithm_description(algorithm)
    encapsulation_size = establishment["ciphertext_size"]

    rows: List[Dict[str, Any]] = []
    for data_size in data_sizes:
        aes_key = establish_aes_key(algorithm, mlkem_details)
        plaintext = secrets.token_bytes(data_size)
        (
            encryption,
            decryption,
            encryption_memory,
            decryption_memory,
            aes_ciphertext_size,
        ) = benchmark_aes(aes_key, plaintext, repetitions)
        rows.append(
            {
                "Algorithm": algorithm,
                "Algorithm Type": algorithm_type,
                "Average Key Generation Time (ms)": key_generation["average"],
                "Minimum Key Generation Time (ms)": key_generation["minimum"],
                "Maximum Key Generation Time (ms)": key_generation["maximum"],
                "Key Generation Std Dev (ms)": key_generation["std_dev"],
                "Average Key Establishment/Transport Time (ms)": establishment[
                    "average"
                ],
                "Minimum Key Establishment/Transport Time (ms)": establishment[
                    "minimum"
                ],
                "Maximum Key Establishment/Transport Time (ms)": establishment[
                    "maximum"
                ],
                "Key Establishment Std Dev (ms)": establishment["std_dev"],
                "Average AES Encryption Time (ms)": encryption["average"],
                "Average AES Decryption Time (ms)": decryption["average"],
                "AES-GCM Ciphertext Size (bytes)": aes_ciphertext_size,
                "AES Encryption Throughput (MiB/s)": _throughput_mib_per_second(
                    data_size, encryption["average"]
                ),
                "AES Decryption Throughput (MiB/s)": _throughput_mib_per_second(
                    data_size, decryption["average"]
                ),
                "Peak Python Memory - AES Encryption (bytes)": encryption_memory,
                "Peak Python Memory - AES Decryption (bytes)": decryption_memory,
                "Public Key Size (bytes)": int(key_generation["public_size"]),
                "Private Key Size (bytes)": int(key_generation["private_size"]),
                "Encapsulation or Ciphertext Size (bytes)": encapsulation_size,
                "Test Data Size (bytes)": data_size,
                "Correctness Verification": "Passed",
                "Quantum Resistance Classification": quantum_classification,
                "Performance Score (0-100)": None,
                "Status": "OK",
                "Error": "",
            }
        )
    return rows


def _add_performance_scores(
    results: pd.DataFrame, weights: Dict[str, float]
) -> pd.DataFrame:
    """Min-max normalize lower-is-better timings per payload size, then weight them."""
    scored = results.copy()
    scored["Performance Score (0-100)"] = float("nan")
    metric_names = list(TIME_METRICS.values())
    total_weight = sum(weights.values())
    if total_weight <= 0:
        raise ValueError("At least one performance scoring weight must be greater than 0.")

    for data_size, group in scored.groupby("Test Data Size (bytes)"):
        valid = group[group["Status"] == "OK"]
        if valid.empty:
            continue

        row_scores = pd.Series(0.0, index=valid.index)
        for weight_name, metric_name in TIME_METRICS.items():
            weight = weights[weight_name] / total_weight
            values = pd.to_numeric(valid[metric_name], errors="coerce")
            minimum = values.min()
            maximum = values.max()
            if pd.isna(minimum) or pd.isna(maximum):
                continue
            if maximum == minimum:
                normalized = pd.Series(100.0, index=valid.index)
            else:
                normalized = 100 * (maximum - values) / (maximum - minimum)
            row_scores += normalized * weight
        scored.loc[valid.index, "Performance Score (0-100)"] = row_scores

    return scored


def run_benchmarks(
    repetitions: int,
    data_sizes: Sequence[int],
    weights: Dict[str, float],
    mlkem_available: bool,
    mlkem_details: Optional[Dict[str, Any]],
    mlkem_error: str,
) -> pd.DataFrame:
    """Run uncached measurements and return one report row per algorithm and payload."""
    if not 1 <= repetitions <= 100:
        raise ValueError("Repetitions must be between 1 and 100.")
    if not data_sizes:
        raise ValueError("Select at least one sample-data size.")
    if any(size not in SUPPORTED_DATA_SIZES.values() for size in data_sizes):
        raise ValueError("Only the listed sample-data sizes are supported.")
    if sum(weights.values()) <= 0:
        raise ValueError("At least one performance scoring weight must be greater than 0.")

    rows: List[Dict[str, Any]] = []
    for algorithm in ALGORITHM_NAMES:
        if algorithm == MLKEM_NAME and not mlkem_available:
            rows.extend(
                _empty_result_row(
                    algorithm,
                    data_size,
                    "Unavailable",
                    mlkem_error or "ML-KEM-768 is not available.",
                )
                for data_size in data_sizes
            )
            continue
        try:
            rows.extend(
                _benchmark_one_algorithm(
                    algorithm, repetitions, data_sizes, mlkem_details
                )
            )
        except (
            AttributeError,
            ImportError,
            InvalidTag,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as error:
            rows.extend(
                _empty_result_row(
                    algorithm,
                    data_size,
                    "Failed",
                    f"{type(error).__name__}: {error}",
                )
                for data_size in data_sizes
            )

    results = pd.DataFrame(rows)
    return _add_performance_scores(results, weights)


def _draw_bar_chart(
    results: pd.DataFrame,
    metric: str,
    title: str,
    y_label: str,
    alternative_text: str,
) -> None:
    """Draw one labeled, unit-consistent chart from measured report rows."""
    valid = results[results["Status"] == "OK"].dropna(subset=[metric])
    figure, axis = plt.subplots(figsize=(7, 4))
    if valid.empty:
        axis.text(
            0.5,
            0.5,
            "No measured values available",
            horizontalalignment="center",
            verticalalignment="center",
            transform=axis.transAxes,
        )
        axis.set_xticks([])
        axis.set_yticks([])
    else:
        colors = {
            "RSA-2048": "#5271ff",
            "X25519": "#28a879",
            "ML-KEM-768": "#e6a23c",
        }
        axis.bar(
            valid["Algorithm"],
            valid[metric].astype(float),
            color=[colors[name] for name in valid["Algorithm"]],
        )
        axis.tick_params(axis="x", labelrotation=15)
    axis.set_title(title)
    axis.set_ylabel(y_label)
    figure.tight_layout()
    st.pyplot(figure, clear_figure=True, alt=alternative_text)
    plt.close(figure)


def _render_conclusion(results: pd.DataFrame, score_size: int) -> None:
    """Explain the performance-only winner separately from security suitability."""
    selected = results[
        (results["Test Data Size (bytes)"] == score_size)
        & (results["Status"] == "OK")
    ].dropna(subset=["Performance Score (0-100)"])

    st.subheader("Best-performing algorithm and conclusion")
    if selected.empty:
        st.warning(
            "No complete measurements are available for the selected payload size, "
            "so a performance winner cannot be determined."
        )
        return

    highest_score = selected["Performance Score (0-100)"].max()
    leaders = selected[
        selected["Performance Score (0-100)"].sub(highest_score).abs() < 1e-9
    ]["Algorithm"].tolist()
    mlkem_is_available = MLKEM_NAME in results.loc[
        results["Test Data Size (bytes)"] == score_size, "Algorithm"
    ].tolist() and (
        results.loc[
            (results["Test Data Size (bytes)"] == score_size)
            & (results["Algorithm"] == MLKEM_NAME),
            "Status",
        ].iloc[0]
        == "OK"
    )

    st.write(
        f"For the {score_size:,}-byte payload and the configured performance-only "
        f"weights, the highest normalized score is **{highest_score:.2f}/100** "
        f"({', '.join(leaders)})."
    )
    if MLKEM_NAME in leaders:
        if len(leaders) > 1:
            st.info(
                "ML-KEM-768 is tied for the highest measured performance-only "
                "score under these settings."
            )
        st.success(
            "Based on the measured benchmark results and the evaluated security "
            "requirements, ML-KEM-768 is the preferred post-quantum "
            "key-establishment algorithm for this project. It provides "
            "post-quantum security protection while enabling AES-256-GCM for "
            "secure data encryption. The final selection should consider measured "
            "performance, communication overhead, and security requirements."
        )
    elif mlkem_is_available:
        st.info(
            f"{', '.join(leaders)} has the highest measured performance-only "
            "score under these settings. That does not make it more secure: "
            "RSA-2048 and X25519 are not considered resistant to a sufficiently "
            "capable cryptographically relevant quantum computer. ML-KEM-768 "
            "may still be preferred when post-quantum security is a primary "
            "requirement, despite a slower result or larger public-key messages."
        )
    else:
        st.warning(
            "ML-KEM-768 was unavailable, so these partial measurements cannot "
            "determine a post-quantum performance winner. Install and enable "
            "liboqs before drawing a three-algorithm conclusion."
        )

    st.caption(
        "The score is performance-only. It min-max normalizes the four measured "
        "time metrics for the selected payload and combines them using the "
        "configured weights. It is relative to this run and is not a security score."
    )


def _render_file_encryption_demo(
    mlkem_available: bool,
    mlkem_details: Optional[Dict[str, Any]],
    mlkem_error: str,
) -> None:
    """Encrypt uploaded data to an in-session ciphertext without writing plaintext."""
    st.subheader("Encrypted file sharing demo")
    st.write(
        "Upload a file, choose a key-establishment workflow, and encrypt it with "
        "AES-256-GCM. The app retains only the encrypted bundle and its temporary "
        "session key in Streamlit session memory; it does not write plaintext or "
        "ciphertext files to disk."
    )
    st.caption(
        "The temporary key is not included in the downloaded encrypted bundle. "
        "You can decrypt it only in this active browser session. For real sharing, "
        "use authenticated recipient keys and a reviewed key-management protocol."
    )
    available_algorithms = ["RSA-2048", "X25519"]
    if mlkem_available:
        available_algorithms.append(MLKEM_NAME)
    else:
        st.caption(f"ML-KEM-768 unavailable for this file demo: {mlkem_error}")

    uploaded_file = st.file_uploader(
        "Choose a file to encrypt (maximum 10 MiB)",
        key="file_encryption_upload",
        max_upload_size=10,
    )
    selected_algorithm = st.selectbox(
        "Key-establishment algorithm for file encryption",
        options=available_algorithms,
        key="file_encryption_algorithm",
    )
    if st.button("Encrypt uploaded file", key="encrypt_uploaded_file"):
        if uploaded_file is None:
            st.error("Choose a file before starting encryption.")
        elif uploaded_file.size > MAX_UPLOAD_SIZE_BYTES:
            st.error("The selected file exceeds the 10 MiB demo limit.")
        else:
            try:
                file_plaintext = uploaded_file.getvalue()
                file_key = establish_aes_key(
                    selected_algorithm, mlkem_details
                )
                encrypted_bundle = encrypt_file_payload(file_plaintext, file_key)
                st.session_state["encrypted_file_bundle"] = encrypted_bundle
                st.session_state["encrypted_file_key"] = file_key
                st.session_state["encrypted_file_name"] = uploaded_file.name
                st.session_state["encrypted_file_algorithm"] = selected_algorithm
                st.success(
                    f"Encrypted {len(file_plaintext):,} bytes with "
                    f"{selected_algorithm}; plaintext was not saved to disk."
                )
                del file_plaintext
            except (InvalidTag, OSError, RuntimeError, TypeError, ValueError) as error:
                st.error(
                    f"File encryption failed: {type(error).__name__}: {error}"
                )

    encrypted_bundle = st.session_state.get("encrypted_file_bundle")
    file_key = st.session_state.get("encrypted_file_key")
    if encrypted_bundle is not None and file_key is not None:
        encrypted_name = st.session_state["encrypted_file_name"]
        original_name = encrypted_name
        algorithm = st.session_state["encrypted_file_algorithm"]
        with st.container(border=True):
            st.write(
                f"Encrypted bundle ready ({len(encrypted_bundle):,} bytes) "
                f"using {algorithm}."
            )
            st.download_button(
                "Download encrypted file",
                data=encrypted_bundle,
                file_name=f"{encrypted_name}.pqcenc",
                mime="application/octet-stream",
                key="download_encrypted_file",
            )
            prepare_decryption = st.checkbox(
                "Prepare decrypted file download for this session",
                key="prepare_decrypted_file_download",
            )
            if prepare_decryption:
                try:
                    plaintext = decrypt_file_payload(encrypted_bundle, file_key)
                    st.success(
                        f"Decryption and authentication succeeded "
                        f"({len(plaintext):,} bytes)."
                    )
                    st.download_button(
                        "Download decrypted file",
                        data=plaintext,
                        file_name=original_name,
                        mime="application/octet-stream",
                        key="download_decrypted_file",
                    )
                    del plaintext
                except (InvalidTag, TypeError, ValueError) as error:
                    st.error(
                        f"File decryption failed: {type(error).__name__}: {error}"
                    )
            if st.button("Clear encrypted file and session key", key="clear_file_demo"):
                for state_key in (
                    "encrypted_file_bundle",
                    "encrypted_file_key",
                    "encrypted_file_name",
                    "encrypted_file_algorithm",
                ):
                    st.session_state.pop(state_key, None)
                st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="Classical vs post-quantum key establishment",
        page_icon=":material/monitoring:",
        layout="wide",
    )
    st.title("Performance evaluation of classical and post-quantum key exchange")
    st.write(
        "Measure RSA-2048 key transport, X25519 key agreement, and ML-KEM-768 "
        "key encapsulation on this computer. AES-256-GCM encrypts the sample "
        "data after each workflow produces a session key."
    )

    description_columns = st.columns(3)
    descriptions = (
        (
            "RSA-2048",
            "Classical RSA-OAEP key transport: a random 32-byte AES session key "
            "is encrypted to the receiver and unwrapped by its private key. "
            "This is key transport, not a true key exchange.",
        ),
        (
            "X25519",
            "Classical elliptic-curve Diffie-Hellman. Two parties create "
            "ephemeral key pairs and independently derive the same shared "
            "secret, expanded with HKDF-SHA-256.",
        ),
        (
            "ML-KEM-768",
            "NIST-standardized post-quantum key encapsulation (FIPS 203). "
            "The sender encapsulates a secret to the receiver's public key; "
            "the receiver decapsulates it. HKDF-SHA-256 derives the AES key.",
        ),
    )
    for column, (name, description) in zip(description_columns, descriptions):
        with column:
            with st.container(border=True):
                st.subheader(name)
                st.write(description)

    mlkem_available, mlkem_details, mlkem_error = inspect_mlkem_support()
    if mlkem_available:
        st.success("ML-KEM-768 is available through the native liboqs library.")
    else:
        st.warning(
            f"ML-KEM-768 is not available: {mlkem_error} "
            "No substitute algorithm will be used; any run will label it unavailable."
        )

    with st.sidebar:
        st.header("Benchmark configuration")
        repetitions = st.number_input(
            "Repetitions per operation",
            min_value=1,
            max_value=100,
            value=10,
            step=1,
            help="Use more repetitions for a steadier estimate; RSA key generation "
            "and 1 MB samples make longer runs take more time. Use 100 for final "
            "academic measurements when practical.",
        )
        selected_size_labels = st.multiselect(
            "Sample data sizes",
            options=list(SUPPORTED_DATA_SIZES),
            default=list(SUPPORTED_DATA_SIZES),
        )
        score_size_label = st.selectbox(
            "Payload size used for the performance conclusion",
            options=list(SUPPORTED_DATA_SIZES),
            index=2,
        )
        st.markdown("**Performance-only score weights**")
        weights = {
            "key_generation": float(
                st.slider("Key generation", min_value=0, max_value=100, value=25, step=5)
            ),
            "establishment": float(
                st.slider(
                    "Key establishment / transport",
                    min_value=0,
                    max_value=100,
                    value=25,
                    step=5,
                )
            ),
            "encryption": float(
                st.slider("AES encryption", min_value=0, max_value=100, value=25, step=5)
            ),
            "decryption": float(
                st.slider("AES decryption", min_value=0, max_value=100, value=25, step=5)
            ),
        }
        st.caption("Weights are normalized by their sum; at least one must be nonzero.")
        run_clicked = st.button(
            "Run benchmark",
            type="primary",
            width="stretch",
        )

    if run_clicked:
        selected_sizes = [
            SUPPORTED_DATA_SIZES[label] for label in selected_size_labels
        ]
        score_size = SUPPORTED_DATA_SIZES[score_size_label]
        if not selected_sizes:
            st.error("Select at least one sample-data size.")
        elif score_size not in selected_sizes:
            st.error(
                "The payload size used for scoring must also be selected for testing."
            )
        elif sum(weights.values()) <= 0:
            st.error("Set at least one performance scoring weight above zero.")
        else:
            try:
                with st.spinner(
                    "Running real cryptographic operations on this computer..."
                ):
                    measured_results = run_benchmarks(
                        repetitions=int(repetitions),
                        data_sizes=selected_sizes,
                        weights=weights,
                        mlkem_available=mlkem_available,
                        mlkem_details=mlkem_details,
                        mlkem_error=mlkem_error,
                    )
                st.session_state["benchmark_results"] = measured_results
                st.session_state["benchmark_run"] = {
                    "time": datetime.now().astimezone().isoformat(timespec="seconds"),
                    "repetitions": int(repetitions),
                    "sizes": selected_sizes,
                    "score_size": score_size,
                    "weights": weights.copy(),
                }
            except (InvalidTag, OSError, RuntimeError, TypeError, ValueError) as error:
                st.error(f"Benchmark could not be completed: {type(error).__name__}: {error}")

    _render_file_encryption_demo(
        mlkem_available=mlkem_available,
        mlkem_details=mlkem_details,
        mlkem_error=mlkem_error,
    )

    results = st.session_state.get("benchmark_results")
    run_info = st.session_state.get("benchmark_run")
    if results is None or run_info is None:
        st.info(
            "Configure the repetitions, payload sizes, and score weights, then "
            "select **Run benchmark**. Measurements are not cached."
        )
        st.subheader("Security comparison")
        security_rows = [
            {
                "Algorithm": algorithm,
                "Quantum resistance classification": _algorithm_description(algorithm)[1],
            }
            for algorithm in ALGORITHM_NAMES
        ]
        st.dataframe(
            pd.DataFrame(security_rows),
            hide_index=True,
            alt="Quantum-security classifications for the three algorithms",
        )
        return

    st.caption(
        f"Measured at {run_info['time']} · {run_info['repetitions']} repetitions · "
        f"{len(run_info['sizes'])} payload size(s). Selecting Run benchmark creates "
        "a fresh measurement; displayed prior results retain their original timestamp."
    )
    st.subheader("Performance comparison")
    st.dataframe(
        results,
        hide_index=True,
        alt="Measured key, establishment, AES, key-size, correctness, and score results",
    )
    st.download_button(
        "Download benchmark report (CSV)",
        data=results.to_csv(index=False).encode("utf-8"),
        file_name="cryptography_performance_benchmark.csv",
        mime="text/csv",
    )

    unavailable_rows = results[results["Status"] != "OK"]
    for _, row in unavailable_rows.drop_duplicates("Algorithm").iterrows():
        st.error(
            f"{row['Algorithm']} — {row['Status']}: {row['Error']}",
            icon=":material/error:",
        )

    score_size = run_info["score_size"]
    chart_data = results[results["Test Data Size (bytes)"] == score_size]
    st.subheader("Measured comparison charts")
    st.caption(
        "AES timings and the performance score use the selected "
        f"{score_size:,}-byte payload. Size charts use serialized/raw key sizes "
        "reported by the relevant cryptographic library."
    )
    chart_specs = (
        (
            "Average Key Generation Time (ms)",
            "Key generation time",
            "Time (ms)",
            "Average measured key-pair generation time in milliseconds",
        ),
        (
            "Average Key Establishment/Transport Time (ms)",
            "Key establishment / RSA key transport time",
            "Time (ms)",
            "Average measured shared-secret establishment or RSA key-transport time",
        ),
        (
            "Average AES Encryption Time (ms)",
            "AES-256-GCM encryption time",
            "Time (ms)",
            "Average measured AES-256-GCM encryption time for the selected payload",
        ),
        (
            "Average AES Decryption Time (ms)",
            "AES-256-GCM decryption time",
            "Time (ms)",
            "Average measured AES-256-GCM decryption time for the selected payload",
        ),
        (
            "AES Encryption Throughput (MiB/s)",
            "AES encryption throughput",
            "Throughput (MiB/s)",
            "Measured AES encryption throughput in mebibytes per second",
        ),
        (
            "AES Decryption Throughput (MiB/s)",
            "AES decryption throughput",
            "Throughput (MiB/s)",
            "Measured AES decryption throughput in mebibytes per second",
        ),
        (
            "Peak Python Memory - AES Encryption (bytes)",
            "Peak traced Python memory during encryption",
            "Peak memory (bytes)",
            "Peak traced Python allocation during AES encryption, excluding native allocations",
        ),
        (
            "Peak Python Memory - AES Decryption (bytes)",
            "Peak traced Python memory during decryption",
            "Peak memory (bytes)",
            "Peak traced Python allocation during AES decryption, excluding native allocations",
        ),
        (
            "Public Key Size (bytes)",
            "Public key size",
            "Size (bytes)",
            "Serialized public-key size in bytes for each measured algorithm",
        ),
        (
            "Private Key Size (bytes)",
            "Private key size",
            "Size (bytes)",
            "Serialized or standardized private-key size in bytes; private keys are not displayed",
        ),
        (
            "Encapsulation or Ciphertext Size (bytes)",
            "Encapsulation / ciphertext size",
            "Size (bytes)",
            "RSA-OAEP or ML-KEM encapsulation ciphertext size; X25519 has no ciphertext",
        ),
        (
            "Performance Score (0-100)",
            "Performance-only score",
            "Normalized score (0-100)",
            "Configured weighted score from normalized timing measurements, not a security score",
        ),
    )
    chart_columns = st.columns(2)
    for index, (metric, title, y_label, alt_text) in enumerate(chart_specs):
        with chart_columns[index % 2]:
            with st.container(border=True):
                _draw_bar_chart(chart_data, metric, title, y_label, alt_text)
                if metric == "Encapsulation or Ciphertext Size (bytes)":
                    st.caption(
                        "X25519 performs key agreement by exchanging public keys; "
                        "it has no encapsulation ciphertext."
                    )

    st.subheader("Security comparison")
    security_rows = [
        {
            "Algorithm": algorithm,
            "Quantum resistance classification": _algorithm_description(algorithm)[1],
        }
        for algorithm in ALGORITHM_NAMES
    ]
    st.dataframe(
        pd.DataFrame(security_rows),
        hide_index=True,
        alt="Security limitations and quantum-resistance classifications",
    )
    st.write(
        "AES-256-GCM performs the bulk data encryption and authenticates ciphertext. "
        "The public-key algorithm only transports or establishes the AES key; the "
        "reported AES times exclude public-key operations. Unique 96-bit nonces are "
        "generated for each encryption under a given AES key."
    )
    _render_conclusion(results, score_size)


if __name__ == "__main__":
    main()