# Deliberately insecure test fixtures

This repository is for validating SCA, SAST, secret, IaC, container and SBOM
scanners. It deliberately contains outdated dependencies, unsafe code
patterns, fake hard-coded credentials, a throwaway RSA key, and insecure
infrastructure settings. Do not deploy or reuse these patterns.

Every credential is either a documented public example, a syntactically valid
but randomly generated fake, or (for `config/fixture_key.pem`) a key generated
solely for this repository and never used anywhere.
