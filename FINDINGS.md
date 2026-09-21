# Findings inventory

What each fixture is meant to trigger, by scanner category.

## SAST — `src/`

| File | Function | Weakness | CWE |
|------|----------|----------|-----|
| `app.cpp` | `login` | Hard-coded credentials, plaintext password in log | 798, 532 |
| `app.cpp` | globals `password_admin`, `secret_key_api`, … | `const char *` credential literals | 798 |
| `app.cpp` | `issueSessionToken` | `rand()` seeded with `time()` | 330, 338 |
| `app.cpp` | `verifyApiKey` | Early-exit comparison (timing) | 208 |
| `vulnerable.cpp` | `unsafeQuery`, `findUser` | SQL built by concatenation, run via `sqlite3_exec` | 89 |
| `vulnerable.cpp` | `findUserById` | `sprintf`-built SQL (C-string) | 89 |
| `vulnerable.cpp` | `changePassword` | `sprintf` into fixed buffer + SQL injection | 120, 89 |
| `injection.cpp` | `ping` | `system()` with user input | 78 |
| `injection.cpp` | `runTool` | `popen()` with user input | 78 |
| `injection.cpp` | `logMessage`, `syslog_like` | Format string via `printf`/`snprintf`/`vsprintf` | 134 |
| `injection.cpp` | `readUserFile` | Path traversal | 22 |
| `injection.cpp` | `ldapFilter` | LDAP injection | 90 |
| `memory.cpp` | `copyName` | `strcpy`/`strcat` overflow | 120, 121 |
| `memory.cpp` | `formatGreeting` | `sprintf %s` overflow | 120 |
| `memory.cpp` | `readLine` | `gets()` | 242 |
| `memory.cpp` | `clearBuffer` | `memset(p, 0, sizeof(p))` on a pointer | 467 |
| `memory.cpp` | `stackName` | Returns address of stack array | 562 |
| `memory.cpp` | `parseHeader` | Length from wire trusted for `memcpy` | 125, 787 |
| `memory.cpp` | `sumArray` | Caller-supplied bound, unchecked `operator[]` | 129 |
| `memory.cpp` | `useAfterFree` | Use after free | 416 |
| `memory.cpp` | `doubleFree` | Double `delete[]` | 415 |
| `memory.cpp` | `allocateRecords` | Integer overflow before `new[]` | 190 |
| `memory.cpp` | `uninitialisedRead` | Uninitialised local | 457 |
| `crypto.cpp` | `weakHash` | MD5 for passwords | 328 |
| `crypto.cpp` | `sha1Hash` | SHA-1 | 328 |
| `crypto.cpp` | `generateToken` | `rand()` for tokens | 338 |
| `crypto.cpp` | `encryptEcb` | DES, ECB mode, hard-coded key | 327, 329, 321 |
| `crypto.cpp` | `pbkdfWeak` | PBKDF2 with 1 iteration, static salt | 916 |
| `network.cpp` | `fetchInsecure` | `CURLOPT_SSL_VERIFYPEER=0`, http://, creds in URL | 295, 319 |
| `network.cpp` | `tlsClientNoVerify` | `SSL_VERIFY_NONE`, TLS 1.0, NULL/RC4/DES ciphers | 295, 326 |
| `network.cpp` | `buildCallbackUrl` | Open redirect, token in query string | 601, 598 |
| `files.cpp` | `makeTempFile` | `tmpnam`, `mktemp` | 377 |
| `files.cpp` | `writeWorldWritable` | `open(..., 0777)`, `chmod 0777` | 732 |
| `files.cpp` | `tocTouRead` | `access()` then `fopen()` | 367 |
| `files.cpp` | `extractArchiveEntry` | Zip-slip | 22 |
| `files.cpp` | `deserializeRecord` | `reinterpret_cast` of wire bytes, calls embedded function pointer | 502 |
| `tools/gen-docs.js` | — | `eval`, `execSync` concat, prototype pollution, unsafe YAML | 94, 78, 1321 |
| `CMakeLists.txt` | — | No stack protector / FORTIFY / PIE, `execstack`, `GIT_TAG master`, http:// git URL | 693, 494 |

## Secrets

| Location | Type |
|----------|------|
| `src/secrets.hpp` | AWS key pair + session token, GitHub PAT/OAuth, GitLab PAT, Slack bot token + webhook, Stripe live keys, SendGrid, Twilio, Google API key, Mailgun, npm token, 4 DB connection strings, JWT secret + signed JWT, AES key/IV, RSA private key PEM |
| `.env` | AWS, GitHub, Slack, Stripe, SendGrid, DB URLs, JWT secret, admin password |
| `.npmrc` | `_authToken`, `strict-ssl=false`, http registry |
| `config/fixture_key.pem` | RSA private key (throwaway) |
| `config/database.yml`, `config/app.ini` | DB passwords, AWS keys, SMTP password, API key |
| `terraform/provider.tf`, `terraform/secrets.tf`, `terraform/rds.tf` | Provider access keys, RDS master password, Lambda env secrets |
| `kubernetes/deployment.yaml`, `kubernetes/secret.yaml` | Env secrets, base64 Secret manifest |
| `Dockerfile`, `docker-compose.yml`, `cloudformation/stack.yaml`, `ansible/playbook.yml`, `.github/workflows/insecure-ci.yml` | Baked-in AWS keys, DB passwords, tokens |

## SCA

| Manifest | Ecosystem | Notable vulnerable pins |
|----------|-----------|-------------------------|
| `conanfile.txt`, `conan.lock` | Conan | openssl 1.0.2u, zlib 1.2.11, libcurl 7.68.0, libxml2 2.9.10, expat 2.2.9, libpng 1.6.36, sqlite3 3.31.1, boost 1.71.0, protobuf 3.11.4, poco 1.9.4, libssh2 1.9.0, pcre 8.43, libtiff 4.1.0, openjpeg 2.3.1 |
| `vcpkg.json` | vcpkg | Same set via `overrides`, 2020.04 baseline |
| `CMakeLists.txt` | FetchContent | fmt 6.1.2, nlohmann_json 3.7.0, spdlog 1.5.0, googletest 1.10.0, cpp-httplib `master` |
| `requirements.txt` | pip | conan 1.40.0, pyyaml 5.3.1, requests 2.19.1, urllib3 1.24.1, jinja2 2.10, cryptography 2.3, paramiko 2.4.1, lxml 4.6.2, pillow 6.2.0 |
| `package.json`, `package-lock.json` | npm | lodash 4.17.15, minimist 1.2.0, node-forge 0.9.0, handlebars 4.1.2, marked 0.3.9, axios 0.18.0, serialize-javascript 2.1.0, js-yaml 3.12.0, ws 5.2.2; `postinstall` curl beacon |
| `Dockerfile` | OS packages | ubuntu:18.04 (EOL), unpinned apt |
| `docker-compose.yml` | Images | postgres:9.6, redis:5.0 |
| `terraform/versions.tf` | Providers | hashicorp/aws 3.0.0 |

## IaC

| File | Findings |
|------|----------|
| `terraform/provider.tf` | Static creds in provider, unencrypted S3 backend |
| `terraform/insecure.tf` | Public-read-write S3 + wildcard bucket policy, EC2 public IP + IMDSv1 + unencrypted root + secrets in user_data, unencrypted EBS, weak CloudTrail |
| `terraform/network.tf` | SG 0.0.0.0/0 and ::/0 on 22/3389/5432/all, default VPC, public subnet, no flow logs |
| `terraform/rds.tf` | Public unencrypted RDS with hard-coded password, no backups/deletion protection, inline Secrets Manager value, Lambda env secrets, nodejs12.x |
| `terraform/iam.tf` | `Action:*`/`Resource:*`, `Principal:*` trust, AdministratorAccess on a user, static access key, weak password policy |
| `kubernetes/deployment.yaml` | privileged, root, hostNetwork/PID/IPC, SYS_ADMIN caps, hostPath `/` + docker.sock, `:latest`, no limits/probes, env secrets |
| `kubernetes/secret.yaml` | Secret manifest committed, NodePort service |
| `kubernetes/rbac.yaml` | cluster-admin to default SA and `system:authenticated`, wildcard ClusterRole |
| `cloudformation/stack.yaml` | Public bucket, open SG, public unencrypted RDS with default password (`NoEcho: false`), star IAM, secrets in UserData |
| `ansible/playbook.yml` | Secrets in vars, `validate_certs: false`, `curl \| bash`, mode 0777, root SSH, firewall off, NOPASSWD sudo |
| `Dockerfile` | EOL base, ENV secrets, unpinned apt, `curl \| bash`, `ADD` from URL, PEM copied into image, chmod 777, root password, `USER root`, EXPOSE 22 |
| `docker-compose.yml` | privileged, host net/pid/ipc, cap ALL, seccomp/apparmor unconfined, `/` and docker.sock mounts, secrets in env, `trust` auth, redis unprotected |
| `.github/workflows/insecure-ci.yml` | `pull_request_target` + PR head checkout, `permissions: write-all`, expression injection, secrets echoed, `curl \| bash`, unpinned actions |

## SBOM — `sbom/`

`bom.cdx.json` (CycloneDX 1.5) and `sbom.spdx.json` (SPDX 2.3) list the 30
Conan packages with `pkg:conan/...` purls. Feed either to
`tigergate-scanner upload`, `trivy sbom`, or `grype sbom:`.
