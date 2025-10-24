# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.x     | :white_check_mark: |
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

## Reporting a Vulnerability

We take the security of this project seriously. If you discover a security vulnerability, please follow these steps:

### How to Report

1. **Do NOT** open a public issue for security vulnerabilities
2. Email the maintainer directly at: [tu2090@nyu.edu]
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Initial Response**: Within 48 hours of report submission
- **Status Update**: Weekly updates on the progress
- **Resolution Timeline**: Critical vulnerabilities will be addressed within 7 days

### Security Update Process

1. Vulnerability is confirmed and assessed
2. Fix is developed and tested
3. Security advisory is prepared
4. Patch is released with security notes
5. Public disclosure after fix is available

## Security Best Practices for Contributors

- Never commit secrets, API keys, or credentials
- Use pre-commit hooks to scan for secrets
- Keep dependencies up to date
- Follow secure coding practices
- Review code for potential vulnerabilities before submitting

## Known Security Considerations

- This project handles cryptographic operations - ensure proper certificate validation
- API calls to Rekor log should use HTTPS
- Verify signatures before trusting artifact integrity

## Contact

For security-related questions that are not vulnerabilities, please open a regular issue on GitHub.