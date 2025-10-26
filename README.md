# Software Supply Chain Security - Assignment Project

## Description
This project implements a Python-based verification system for Sigstore's Rekor transparency log. It demonstrates software supply chain security concepts including artifact signing, signature verification, and transparency log consistency validation.

## Features
- Sign artifacts using cosign
- Verify signatures from Rekor transparency log
- Validate Merkle tree inclusion proofs
- Verify log consistency between checkpoints

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- cosign (Sigstore signing tool)
- rekor-cli (Rekor command-line interface)

### Install System Dependencies
```bash
# Install cosign
brew install cosign

# Install rekor-cli
brew install rekor-cli
```

### Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

Or using poetry:
```bash
poetry install
```

## Usage

### Sign an Artifact
```bash
cosign sign-blob ./artifact.md --bundle artifact.bundle
```

### Verify Entry in Rekor Log
```bash
python3 rekor_verification.py --log-index YOUR_LOG_INDEX --artifact artifact.md
```

### Get Current Checkpoint
```bash
python3 rekor_verification.py -c
```

### Verify Consistency
```bash
python3 consistency_verifier.py --verify-consistency \
  --old-tree-size OLD_SIZE \
  --old-root-hash OLD_HASH
```

## Project Structure
```
.
├── artifact.md              # Sample artifact file
├── artifact.bundle          # Signed artifact bundle
├── rekor_verification.py    # Main verification script
├── consistency_verifier.py  # Consistency verification
├── merkle_proof.py          # Merkle tree verification
└── tests/                   # Test directory
```

## Dependencies
- requests: HTTP library for API calls
- cryptography: Cryptographic operations
- PyJWT: JSON Web Token handling

## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Security
Please read [SECURITY.md](SECURITY.md) for information on reporting security vulnerabilities.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
NetID: tu2090

## Acknowledgments
- Based on Sigstore tooling (rekor-cli, rekor-monitor)
- Template from python-rekor-monitor-template
