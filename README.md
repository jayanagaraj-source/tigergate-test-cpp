# tigergate-test-cpp

Security-test fixture for **C++**, extended into a full multi-scanner playground.

This repository **deliberately** contains vulnerable code, hard-coded secrets,
outdated dependencies, and insecure infrastructure so you can validate:

| Category | What it exercises | Where |
|----------|-------------------|-------|
| **SAST** | Injection, memory safety, weak crypto, TLS misuse, unsafe file handling | `src/*.cpp` |
| **Secrets** | Cloud keys, tokens, connection strings, JWT, RSA PEM | `src/secrets.hpp`, `.env`, `.npmrc`, `config/`, `terraform/`, `Dockerfile` |
| **SCA** | Known-CVE deps across Conan, vcpkg, pip, npm | `conanfile.txt`, `conan.lock`, `vcpkg.json`, `requirements.txt`, `package-lock.json` |
| **IaC** | Public buckets, open SGs, wildcard IAM, privileged pods, unsafe CI | `terraform/`, `kubernetes/`, `cloudformation/`, `ansible/`, `docker-compose.yml`, `.github/workflows/insecure-ci.yml` |
| **Container** | EOL base image, root user, baked secrets, `curl \| bash` | `Dockerfile` |
| **SBOM** | CycloneDX 1.5 + SPDX 2.3 documents | `sbom/` |

> ⚠️ Everything here is a fixture. Secrets are fake or throwaway; do not
> deploy any of this, and do not copy these patterns into real code.

## Build & run

```bash
make            # build build/tigergate (needs g++, libssl-dev, libsqlite3-dev)
make test       # run unit tests (should PASS)
make asan       # run memory-corruption probes under ASan (should ABORT)
make run        # tigergate version
```

CMake is also supported (`cmake -B build && cmake --build build`); pass
`-DTG_FETCH_DEPS=ON` to pull the pinned FetchContent dependencies.

The CLI routes each subcommand into one vulnerability class:

```bash
./build/tigergate login admin password123     # hard-coded creds
./build/tigergate find "' OR '1'='1"          # SQL injection via sqlite3_exec
./build/tigergate findid "1 OR 1=1"            # sprintf-built SQL
./build/tigergate ping "8.8.8.8; id"          # system() injection
./build/tigergate log '%x %x %x'              # format-string leak
./build/tigergate copy $(printf 'A%.0s' {1..64})   # stack overflow
./build/tigergate hash hunter2                # MD5 password hash
./build/tigergate enc secret                  # DES-ECB, hard-coded key
./build/tigergate tls example.com             # SSL_VERIFY_NONE
./build/tigergate keys                        # embedded secrets
```

## Run the scanners

```bash
docker run --rm -v "$PWD":/src -w /src -e TIGERGATE_API_KEY tigergate/tigergate-cli:latest scan
make scan       # runs whichever of semgrep/trivy/gitleaks/checkov/flawfinder/cppcheck are installed
make sbom       # regenerate SBOMs with syft (if installed)
```

CI runs the full matrix in `.github/workflows/security.yml`.

See **FINDINGS.md** for the complete inventory mapping every fixture to its
scanner category and CWE.
# tigergate-test-cpp
