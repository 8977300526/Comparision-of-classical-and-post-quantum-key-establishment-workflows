# Classical and post-quantum key-establishment benchmark

This Streamlit project measures three real cryptographic workflows on the computer
running the application:

- **RSA-2048** with RSA-OAEP to transport a random 32-byte AES session key. This
  is key transport, not a true two-party key exchange.
- **X25519** with two key pairs and independent shared-secret derivations.
- **ML-KEM-768** with a public-key encapsulation and private-key decapsulation
  using `liboqs-python` and the native `liboqs` library.

AES-256-GCM encrypts the actual sample data after each workflow creates or
transports an AES key. Public-key algorithms are not used to encrypt arbitrary
files directly. The dashboard also provides an encrypted-file demo: it keeps the
encrypted bundle and a temporary AES key in the active Streamlit session and
does not write uploaded plaintext files to disk.

## Requirements

- Windows 10/11 and Python 3.10 or newer (64-bit recommended).
- The Python packages in `requirements.txt`.
- ML-KEM is optional and additionally requires the `liboqs-python` wrapper and a compatible
  native `liboqs` library build with `ML-KEM-768` enabled.

Installing `liboqs-python` alone does **not** guarantee that the native library
or the requested KEM is installed. The app checks availability explicitly,
reports the reason when possible, and never substitutes another algorithm.
If ML-KEM is unavailable, the classical measurements can still run, but the
report marks ML-KEM as unavailable and does not claim a three-algorithm winner.
The wrapper is intentionally not installed by the standard `requirements.txt`;
install it separately only when setting up the optional ML-KEM workflow.

## Install and run in VS Code on Windows

Open the project folder in VS Code, then open **Terminal → New Terminal**. From
the folder containing `app.py`, run:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If using Command Prompt rather than PowerShell, activate with:

```bat
.venv\Scripts\activate.bat
```

Choose the `.venv` interpreter in VS Code with **Python: Select Interpreter** if
VS Code does not select it automatically. Streamlit prints a local address (by
default `http://localhost:8501`) in the terminal.

## ML-KEM / liboqs setup notes

The wrapper calls a native library. A missing native DLL, unsupported wrapper /
native-library combination, or a liboqs build without ML-KEM-768 will be reported
in the app. Do not treat a successful `pip install liboqs-python` as proof that
ML-KEM is available.

### Windows

Native Windows setup depends on the selected Python version, compiler, and
liboqs release. Follow the current build and Python-binding instructions in the
[Open Quantum Safe liboqs repository](https://github.com/open-quantum-safe/liboqs)
and [liboqs-python repository](https://github.com/open-quantum-safe/liboqs-python).
Use a compatible Visual Studio C/C++ toolchain and CMake build, enable
`ML-KEM-768`, and make the resulting native library discoverable on `PATH` before
starting VS Code. Then install / reinstall `liboqs-python` inside the activated
`.venv` and restart the terminal. The exact native build steps can change between
liboqs releases; use the upstream instructions for the version being installed.

### Alternative: WSL 2 (Ubuntu)

If a compatible native Windows build is not available for your machine, install
WSL 2 and Ubuntu, then build the native library there using the upstream
instructions. A typical Ubuntu build-tool setup is:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build git python3-dev python3-venv
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -S . -B build -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DOQS_BUILD_ONLY_LIB=ON
cmake --build build --parallel
sudo cmake --install build
```

Then create a Python virtual environment in the WSL project folder, install the
requirements there, and launch Streamlit from the same WSL terminal. Consult the
upstream build instructions if CMake options differ for the liboqs release you
use. The app must run in the same environment where both the wrapper and native
library are available.

## Dashboard guide

1. Set repetitions (1–100; the initial value is 10), select one or more sample
   sizes, choose which size is used for the performance-only conclusion, and set
   the four score weights. Ten is a quicker initial run; use 100 repetitions
   for final academic measurements when practical.
2. Select **Run benchmark**. Timings are gathered afresh and are not cached.
3. Review the table, charts, security comparison, and dynamic conclusion.
4. Download the report as CSV.
5. In **Encrypted file sharing demo**, encrypt an uploaded file and download its
   `.pqcenc` bundle. Optionally prepare a decrypted download while the same
   browser session and temporary AES key are still active.

The CSV contains one row for each algorithm and selected payload size. Failed or
unavailable operations have an explicit status and explanation instead of a
fabricated value. No private keys or shared secrets are shown or written to the
report. Benchmark results include encryption/decryption throughput in MiB/s and
peak traced Python allocations in bytes.

### Encrypted-file demo storage model

Uploads are read into memory, encrypted with AES-256-GCM, and retained only as
an authenticated encrypted bundle in Streamlit session state. The app does not
create plaintext or ciphertext files on its server filesystem. Its temporary
AES key remains in session memory, is not included in the downloadable bundle,
and is cleared when the file demo is cleared or the session ends. A downloaded
bundle cannot be decrypted in a later session unless the correct key is
independently retained and supplied; this teaching demo intentionally does not
export keys. The decrypted download is prepared in memory on request and is not
saved as a server-side plaintext file. Do not upload sensitive data to an
untrusted deployment.

## Benchmark methodology

- All measured durations use Python's `time.perf_counter()` and are displayed in
  milliseconds. Averages, minima, maxima, and sample standard deviations are
  calculated from the configured repetitions for key generation and key
  establishment / transport.
- RSA key generation creates a fresh 2048-bit key pair for each key-generation
  sample. Public size is DER SubjectPublicKeyInfo; private size is unencrypted
  DER PKCS#8 measured in memory. The key-transport timing uses an already
  generated recipient key and includes generation of a random 32-byte session
  key, OAEP-SHA-256 encryption, and private-key decryption/verification. RSA
  ciphertext size is the length of the actual wrapped-key output measured
  during key transport (256 bytes for a 2048-bit modulus).
- X25519 key generation measures one fresh private/public pair. Establishment
  times two ephemeral key-pair generations and both parties' shared-secret
  derivations and equality check. Each raw public and private key is 32 bytes.
  There is no X25519 ciphertext; parties exchange public keys.
- ML-KEM-768 key generation measures the native KEM key-generation operation.
  The timed establishment operation includes encapsulation, decapsulation, and
  secret comparison, using a recipient public key generated before the timed
  samples. Public/private key sizes come from the enabled liboqs algorithm
  metadata, and ciphertext size is measured from the actual encapsulation output
  and checked against that metadata; secret-key material is not exported to the
  interface.
- The report separately gives the actual AES-GCM ciphertext length, which is
  the payload length plus the 16-byte GCM authentication tag, and the
  encapsulation / RSA transport ciphertext length. X25519 has no
  encapsulation ciphertext.
- Each AES sample uses newly generated test data and a fresh random nonce prefix
  plus a monotonically increasing counter, guaranteeing a distinct 96-bit nonce
  for every encryption under that sample's key. AES encryption and decryption
  are timed separately and each
  plaintext is verified byte-for-byte. Public-key setup, key derivation, and
  data generation are excluded from AES timings.
- AES throughput is computed from the actual average AES operation time and
  payload size as MiB/s. `tracemalloc` measures peak Python-traced allocation
  during separate repeat operations; the memory sampling pass is not included
  in the latency samples. This is not total process RAM and does not include
  allocations inside OpenSSL, liboqs, or other native libraries. Memory and
  throughput figures are therefore implementation/environment indicators, not
  complete hardware memory profiling.
- The uploaded-file demo uses a versioned envelope containing a format marker,
  a unique 12-byte nonce, and AES-GCM ciphertext plus its authentication tag.
  The format marker is authenticated as associated data. Decryption rejects
  malformed or modified bundles. Uploads are limited to 10 MiB.
- RSA transports its random 32-byte AES key directly. X25519 and ML-KEM shared
  secrets are expanded to 32 bytes with HKDF-SHA-256 and a fixed application
  context label. These are educational, unauthenticated exchange examples, not
  a production protocol: identity authentication, certificates, transcript
  binding, and key lifecycle are out of scope.
- The score min-max normalizes each of the four timing measures for the selected
  payload among successful algorithms. Lower times score higher, and the user's
  nonnegative weights are normalized to sum to 1. Identical metric values get
  the same 100 score. The score is relative to the measured algorithms and
  current run only; it is not a security score.
- The app does not cache benchmark results. Timing varies with CPU load, thermal
  state, operating system, native crypto backend, and library version. Use more
  repetitions and repeat runs for academic reporting, and record the machine,
  Python, library, and native liboqs versions alongside exported CSV results.

## Testing

Run the built-in tests from the activated virtual environment:

```powershell
python -m unittest -v
```

The tests exercise RSA key transport, X25519 shared-secret agreement, file
envelope authentication, AES-GCM round trips for all four sample sizes, and
key-size reporting. The ML-KEM tests run when ML-KEM-768 is actually enabled
and otherwise report a skip. Also run the dashboard, encrypt and decrypt a
small uploaded file, and use **Run benchmark** with one repetition and 1 KB data
as a quick end-to-end smoke test; then increase repetitions and data sizes for
measurements.

## Common issues

- **`No module named 'streamlit'` or another package:** activate `.venv` and run
  `python -m pip install -r requirements.txt` using that interpreter.
- **`liboqs-python` imported but `ML-KEM-768` is unavailable:** the wrapper and
  native library are separate. Install a compatible native liboqs build with
  ML-KEM-768 enabled, ensure its DLL / shared library is discoverable, restart
  VS Code, and rerun the app.
- **A native DLL load error on Windows:** confirm the library architecture
  matches 64-bit Python, native runtime dependencies are installed, and the
  library directory is on `PATH`. If the upstream Windows build is unsuitable
  for the machine, use the documented WSL 2 route.
- **PowerShell blocks activation:** use the current-user execution-policy
  guidance from Microsoft, or run `.venv\Scripts\activate.bat` in Command
  Prompt. Do not disable system-wide security policy just for this app.
- **The run takes a long time:** reduce repetitions and/or deselect the 1 MB
  sample. RSA key generation and repeated 1 MB AES operations are intentionally
  real work. Memory measurement makes a separate AES pass so it does not distort
  the recorded latency.

## Illustrative report format (not benchmark results)

The following is a **format-only illustration**. Angle-bracket values are
placeholders, not measured or expected results:

| Algorithm | Key generation (ms) | Establishment / transport (ms) | AES encryption (ms) | AES encryption throughput (MiB/s) | Peak traced Python memory (bytes) | Public key size (bytes) | Correctness | Status |
|---|---:|---:|---:|---:|---:|---:|---|---|
| RSA-2048 | `<measured by app>` | `<measured by app>` | `<measured by app>` | `<derived from measured time>` | `<measured by tracemalloc>` | `<measured DER size>` | Passed / explicit status | OK / Failed |
| X25519 | `<measured by app>` | `<measured by app>` | `<measured by app>` | `<derived from measured time>` | `<measured by tracemalloc>` | `<measured raw size>` | Passed / explicit status | OK / Failed |
| ML-KEM-768 | `<measured by app>` | `<measured by app>` | `<measured by app>` | `<derived from measured time>` | `<measured by tracemalloc>` | `<measured from liboqs>` | Passed / explicit status | OK / Unavailable / Failed |

## Project conclusion

There is no hard-coded winner or pre-filled performance result. The dashboard's
conclusion is computed from the current machine's successful measurements and
selected score weights. It reports the highest performance-only score honestly,
then discusses security independently: RSA-2048 and X25519 are vulnerable to
Shor's algorithm on a sufficiently capable cryptographically relevant quantum
computer, while ML-KEM-768 is standardized as a post-quantum KEM designed to
resist known quantum attacks. ML-KEM may therefore be the appropriate choice
when post-quantum protection is required, even if a classical algorithm has
better raw measured performance. No cryptographic design is guaranteed
absolutely unbreakable.
