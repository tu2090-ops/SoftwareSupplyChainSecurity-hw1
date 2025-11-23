# Software Supply Chain Security - HW1

## Description
This project implements a Python-based verification system for Rekor transparency log. It demonstrates software supply chain security concepts including artifact signing, signature verification, and transparency log consistency validation.

**Student NetID:** tu2090

## Features
- Sign artifacts using cosign with ephemeral certificates
- Verify signatures from Rekor transparency log entries
- Validate Merkle tree inclusion proofs (RFC 6962)
- Verify log consistency between checkpoints
- Command-line interface for all verification operations

## Project Structure
```
.
├── src/
│   └── tu2090_python_rekor_monitor/     # Main package (PyPI location)
│       ├── __init__.py
│       ├── main.py                      # Main verification script with CLI
│       ├── util.py                      # Cryptographic utility functions
│       └── merkle_proof.py              # Merkle tree proof verification (RFC 6962)
├── tests/                               # Test suite
│   ├── __init__.py
│   ├── test.py                          # Core functionality tests
│   └── test_checkpoint.py               # CLI checkpoint tests
├── dist/                                # Built distributions 
│   ├── tu2090_python_rekor_monitor-4.0.0-py3-none-any.whl
│   └── tu2090_python_rekor_monitor-4.0.0.tar.gz
├── cyclonedx-sbom.json                  # Software Bill of Materials 
├── sbom-attestation.bundle              # Cosign attestation 
├── pyproject.toml                       # Poetry dependency configuration
├── poetry.lock                          # Locked dependencies
├── .pre-commit-config.yaml              # Pre-commit hooks (TruffleHog)
├── README.md                            # This file
├── SECURITY.md                          # Security policy
├── CONTRIBUTING.md                      # Contribution guidelines
├── LICENSE                              # MIT License
└── CODEOWNERS                           # Code ownership
```

## Installation

### Prerequisites
- Python 3.10 or higher
- pip or Poetry package manager
- cosign (Sigstore signing tool)
- rekor-cli (Rekor command-line interface)

### Install System Dependencies (macOS)
```bash
# Install cosign
brew install cosign

# Install rekor-cli
brew install rekor-cli

# Verify installations
cosign version
rekor-cli version
```

### Install Python Dependencies

#### Using Poetry (Recommended)
```bash
# Install Poetry if not already installed
curl -sSL https://install.python-poetry.org | python3 -

# Install project dependencies
poetry install

# Activate virtual environment
poetry shell
```

#### Using pip
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux

# Install dependencies
pip install requests cryptography
pip install pytest pytest-cov  # For testing
```
# Install the published package
pip install tu2090-python-rekor-monitor

# Test the CLI
tu2090-python-rekor-monitor --help

# Or install in development environment
pip install tu2090-python-rekor-monitor[dev]

## Usage

### 1. Sign an Artifact
```bash
# Sign artifact with cosign (requires identity verification)
cosign sign-blob ./artifact.md --bundle artifact.bundle
```

This will:
- Open browser for identity verification (GitHub/Google/Microsoft)
- Generate ephemeral certificate
- Sign the artifact
- Store signature in `artifact.bundle`

### 2. Get Current Checkpoint
```bash
# Fetch latest Rekor checkpoint
python main.py -c

# With debug mode (saves to checkpoint.json)
python main.py -d -c
```

### 3. Verify Inclusion Proof
```bash
# Verify artifact signature and inclusion in Rekor log
python main.py --inclusion LOG_INDEX --artifact artifact.md

# With debug output
python main.py -d --inclusion LOG_INDEX --artifact artifact.md
```

This verifies:
- Artifact signature is valid
- Certificate used for signing
- Entry is included in Merkle tree

### 4. Verify Consistency Proof
```bash
# Verify log consistency between two checkpoints
python main.py --consistency \
  --tree-id TREE_ID \
  --tree-size OLD_SIZE \
  --root-hash OLD_ROOT_HASH

### Command-Line Options
```
usage: main.py [-h] [-d] [-c] [--inclusion LOG_INDEX] [--artifact FILEPATH]
               [--consistency] [--tree-id TREE_ID] [--tree-size SIZE]
               [--root-hash HASH]

options:
  -h, --help            Show help message
  -d, --debug           Enable debug mode with verbose output
  -c, --checkpoint      Fetch and display latest checkpoint
  --inclusion INDEX     Verify inclusion proof for log index
  --artifact PATH       Artifact file path for signature verification
  --consistency         Verify consistency between checkpoints
  --tree-id ID          Previous checkpoint tree ID
  --tree-size SIZE      Previous checkpoint tree size
  --root-hash HASH      Previous checkpoint root hash
```
```
### 5. Publication & Supply Chain Security
```bash
Package on PyPI
This package is published on PyPI under the name `tu2090-python-rekor-monitor`.

Links:
- PyPI Package: https://pypi.org/project/tu2090-python-rekor-monitor/
- Install: `pip install tu2090-python-rekor-monitor`
- GitHub Releases: https://github.com/tu2090/python-rekor-monitor/releases

### Supply Chain Security Artifacts

### SBOM (Software Bill of Materials)
- File: `cyclonedx-sbom.json`
- Format: CycloneDX JSON
- Contents: Complete list of dependencies with exact versions
- Purpose: Transparency and vulnerability scanning
- Generated: `poetry run cyclonedx-bom -p -o cyclonedx-sbom.json --format json`

### Cosign Attestation
- File: `sbom-attestation.bundle`
- Type: CycloneDX SBOM attestation
- Signature: Signed with tu2090@nyu.edu identity via Sigstore
- Location: Recorded in Rekor transparency log
- Purpose: Cryptographic proof that SBOM belongs to this package version

### Verify Attestation

```bash
# Verify the attestation
cosign verify-blob-attestation \
  --bundle sbom-attestation.bundle \
  --type cyclonedx \
  --certificate-identity tu2090@nyu.edu \
  --certificate-oidc-issuer https://accounts.google.com \
  --check-claims \
  dist/tu2090_python_rekor_monitor-4.0.0-py3-none-any.whl

# Expected output: Verified OK
```
### Release Information
- **Version:** 4.0.0
- **Release Date:** November 2024
- **Attestation Date:** November 2024
- **Student:** tu2090
- **Course:** Software Supply Chain Security - Fall 2025
```
```
## Testing

### Run Tests
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=. --cov-report=term-missing

# Run specific test file
pytest tests/test.py

# Generate HTML coverage report
pytest --cov=. --cov-report=html
open htmlcov/index.html  # View in browser
```
## Test files:
- `tests/test.py` - Core functionality tests
- `tests/test_checkpoint.py` - CLI checkpoint tests

## Code Modules

### main.py
Main script containing:
- `get_log_entry()` - Fetch log entry by index
- `get_verification_proof()` - Fetch entry with inclusion proof
- `get_latest_checkpoint()` - Fetch current checkpoint
- `inclusion()` - Verify inclusion proof
- `consistency()` - Verify consistency proof
- `main()` - CLI argument parser

### util.py
Cryptographic utilities:
- `extract_public_key()` - Extract public key from X.509 certificate
- `verify_artifact_signature()` - Verify ECDSA signature using public key

### merkle_proof.py
Merkle tree verification (RFC 6962):
- `Hasher` - SHA256 hasher with domain separation
- `verify_inclusion()` - Verify Merkle inclusion proof
- `verify_consistency()` - Verify Merkle consistency proof
- `compute_leaf_hash()` - Compute RFC 6962 leaf hash

## Development

### Pre-commit Hooks

This project uses pre-commit hooks for secret detection:
```bash
# Install pre-commit hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

The `.pre-commit-config.yaml` configures TruffleHog to scan for secrets before each commit.

### Code Quality Tools

Configured in `pyproject.toml`:
- **black** - Code formatting (line length: 100)
- **ruff** - Linting
- **mypy** - Type checking
- **flake8** - Style guide enforcement
- **pylint** - Code analysis
- **bandit** - Security linting

Run code quality checks:
```bash
black .
ruff check .
mypy .
```

## Dependencies

### Runtime Dependencies
- `requests` (^2.31.0) - HTTP library for Rekor API calls
- `cryptography` (^42.0.0) - X.509 certificate handling and signature verification
- `PyJWT` (^2.8.0) - JSON Web Token operations

### Development Dependencies
- `pytest` (^7.4.3) - Testing framework
- `pytest-cov` (^4.1.0) - Coverage reporting
- `mypy` (^1.8.0) - Static type checker
- `black` (^23.12.0) - Code formatter
- `ruff` (^0.1.9) - Fast Python linter
- `flake8` (^7.0.0) - Style checker
- `pylint` (^3.0.3) - Code analyzer
- `bandit` (^1.7.6) - Security checker
- `yclonedx-bom (^3.11.0)` - SBOM generation
- `cosign (system binary)` - Package attestation and verification

## Architecture

### Verification Flow
```
1. Sign Artifact (cosign)
   └─> Creates artifact.bundle with signature + certificate

2. Inclusion Verification
   ├─> Fetch log entry from Rekor
   ├─> Extract signature and certificate
   ├─> Verify artifact signature locally
   ├─> Compute leaf hash (RFC 6962)
   └─> Verify Merkle inclusion proof

3. Consistency Verification
   ├─> Fetch previous checkpoint
   ├─> Fetch latest checkpoint
   ├─> Request consistency proof from Rekor
   └─> Verify Merkle consistency proof
```

### Rekor API Endpoints Used

- `GET /api/v1/log` - Get latest checkpoint
- `GET /api/v1/log/entries?logIndex=N` - Get log entry
- `GET /api/v1/log/entries?logIndex=N&proof=true` - Get entry with proof
- `GET /api/v1/log/proof?firstSize=N&lastSize=M` - Get consistency proof

## Security

See [SECURITY.md](SECURITY.md) for:
- Vulnerability reporting process
- Supported versions
- Security best practices

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code of conduct
- Pull request process
- Code style guidelines
- Testing requirements

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Assignment Information

**Course:** Software Supply Chain Security - Fall 2025  
**Student NetID:** tu2090  
**Assignment:** Assignments

## Acknowledgments

- Based on Sigstore tooling (rekor-cli, rekor-monitor)
- Template inspiration from python-rekor-monitor-template
- RFC 6962: Certificate Transparency
- Sigstore Project: https://www.sigstore.dev/

## Resources

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Rekor API Specification](https://www.sigstore.dev/swagger/)
- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [CycloneDX Specification](https://cyclonedx.org/)

## Troubleshooting

### Common Issues

**Issue:** `ModuleNotFoundError: No module named 'requests'`  
**Solution:** Install dependencies with `poetry install` or `pip install requests cryptography`

**Issue:** Signature verification fails  
**Solution:** Ensure artifact.md hasn't been modified since signing

**Issue:** Inclusion proof verification fails  
**Solution:** Verify you're using the correct log index from artifact.bundle

**Issue:** Pre-commit hook blocks commit  
**Solution:** Secret detected - remove sensitive data before committing

## Contact

For questions or issues related to this assignment:
- Check [SECURITY.md](SECURITY.md) for security concerns
- See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines
- Review course materials and assignment documentation