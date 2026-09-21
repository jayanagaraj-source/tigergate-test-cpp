// Hard-coded credential fixtures for secret-scanner validation.
// NONE of these are real. Formats mirror real providers so regex/entropy
// based detectors (gitleaks, trufflehog, trivy, semgrep p/secrets) fire.
#pragma once

constexpr auto API_KEY = "test-fixture-not-a-real-secret";

// AWS (CWE-798)
constexpr auto AWS_ACCESS_KEY_ID     = "AKIAQ4FIXTURE0TEST01";
constexpr auto AWS_SECRET_ACCESS_KEY = "fx7Q9tZ2mK4pL8wR1nB5vC3yH6jD0sA2eG9uT4iX";
constexpr auto AWS_SESSION_TOKEN     = "FwoGZXIvYXdzEBYaDFixtureSessionTokenNotRealAtAll0000000000000000000000000000000000==";

// GitHub / GitLab
constexpr auto GITHUB_TOKEN          = "ghp_Fixture0TokenNotReal1234567890abcdEFGH";
constexpr auto GITHUB_OAUTH          = "gho_Fixture0TokenNotReal1234567890abcdEFGH";
constexpr auto GITLAB_PAT            = "glpat-FixtureNotRealToken00";

// SaaS / payment
constexpr auto SLACK_BOT_TOKEN       = "xoxb-000000000000-000000000000-FixtureNotRealSlackTok";
constexpr auto SLACK_WEBHOOK         = "https://hooks.slack.com/services/T00000000/B00000000/FixtureNotRealWebhookXXXX";
constexpr auto STRIPE_SECRET_KEY     = "sk_live_FixtureNotReal00000000000000";
constexpr auto STRIPE_PUBLISHABLE    = "pk_live_FixtureNotReal00000000000000";
constexpr auto SENDGRID_API_KEY      = "SG.FixtureNotRealKey0000.FixtureNotRealSecretPart00000000000000000000000";
constexpr auto TWILIO_ACCOUNT_SID    = "AC00000000000000000000000000000000";
constexpr auto TWILIO_AUTH_TOKEN     = "00000000000000000000000000000000";
constexpr auto GOOGLE_API_KEY        = "AIzaSyFixtureNotRealKey0000000000000000";
constexpr auto MAILGUN_KEY           = "key-00000000000000000000000000000000";
constexpr auto NPM_TOKEN             = "npm_FixtureNotRealToken000000000000000000";

// Connection strings with embedded passwords (CWE-259)
constexpr auto DATABASE_URL  = "postgres://admin:password123@db.internal.example.com:5432/tigergate";
constexpr auto MONGO_URI     = "mongodb://root:hunter2@mongo.internal.example.com:27017/admin";
constexpr auto REDIS_URL     = "redis://:fixtureRedisPass@cache.internal.example.com:6379/0";
constexpr auto MYSQL_DSN     = "mysql://app:S3cretFixture!@mysql.internal.example.com:3306/app";
constexpr auto SMTP_PASSWORD = "fixture-smtp-password";
constexpr auto JWT_SECRET    = "fixture-jwt-signing-secret-do-not-use";
constexpr auto ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef";   // 32-byte AES key, hard-coded
constexpr auto ENCRYPTION_IV  = "fedcba9876543210";                   // static IV

// A signed JWT (header.payload.signature) with the secret above.
constexpr auto SAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290IiwiaWF0IjoxNjAwMDAwMDAwfQ.FixtureSignatureNotRealXXXXXXXXXXXXXXXXXXXXX";

// Throwaway RSA private key generated for this fixture (config/fixture_key.pem).
constexpr auto PRIVATE_KEY_PEM =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDUkUaEMH5Q6BE3\n"
"DDgEJbwGvoVv+ILR05hThf8x5LXrMe7mzi+07ua6881aJuiJM3G0R/Ydr53DYemL\n"
"1PFVQ/bMeFf0nj50Fch9MB023BKNbxBB7NsdvmEhWoZ5hi7L5Syz8ubv6XuguqPY\n"
"qQF+HzaDbbiaxd7ph2TiQKUu09DGE1sZuVk1t4zPfwnrwNkS7LIdeed2xAPDpIHg\n"
"648cFZTQvyUI3b3wT7tlM63HQa2Hlj/JO/Wrhq+TdF1MCtYFyT3ImscuhG83v2aH\n"
"mvFj2Aa2YIpYH2Z+bb/LuLoBrS4uijRuC9cten5PolpdcZcNc6QhWYD+Gohy80Gx\n"
"nFn0m3WrAgMBAAECggEACo42smOk+F1wckuDF3r3G0GEoD5MG9pNUU4/gy8IdO8s\n"
"HgU1crS2ieFOqpyqHqknCwebHBO3fh53FjQE4JVyBHj3Y9TOuiEcV/xvm2TZfXFC\n"
"ZFut8LblpGxO/KPFw65bFIoRLSfq0aQNrdX+Mu1JiG8i5AfDufEcTheytRJOZuMX\n"
"Lii/qISHM0XTq1h5HdLP+rj+lYGTjlOsjxgQq1D1Hij2aeHfuylxsHtoRWiYdvFJ\n"
"+J8sNicSqkKNp9XGJeG5VjzR+mCLBzUJyDWjVMXm54mtKu/o6YvuxAa5SKpuKR4q\n"
"OW9EwJo8I8cpYuIRvQoAVGBLAXUlCpz+hM6nH9CSsQKBgQDa0dSMUF2fRqRWXTR8\n"
"lK64aIxxCy5S+hKZCIuEZ9XyCiJY4HTQs+P14mGI4Kc211qKLu4bf1SEZWzfLYQ2\n"
"t2KS8dXNGDHkzlboWkXIZj5kL1KIzdGdg2+B0WJ9L/51cV4QQnd0QeKMdkYkSug0\n"
"bg2cyE9xu3X8IHNkOtc66YT4UQKBgQD4r31hslUYRMTzhcMEgLHp+ctzoK7Ily5r\n"
"J9Y+LBGOwFApK+w3DvUcgUeC4xC2fEhYkIaFK03OjL6DXQ0PBqujOYpTTl0g2AMK\n"
"UU0RV4dQdMkRZSAHNe7Cn9lZSUpM1NVHdvB5FBRrKfP06x8KcQ9veOj3Ay0V2B+N\n"
"wA/Ke67LOwKBgQCeyWdIjsTxYKy+MxJ0WNxU2yEWovtxoSA/xrCfW04oPmxgPDjo\n"
"fbGtayJF1mfg5vM/lQCaGZL2JDeV2Ay6O+cfJLh2BNmn5IeyQlejLXaW8rQcq+Yx\n"
"PAB9nriuiVZIWQTeHa1bQrgoH2eUzHqmGTpti/oCWPssA0xY7k3i5TPlkQKBgCGT\n"
"D8pw2Sw9nJmEJaAl/98m6mDiALb0MkAlULd0G6q6LBhi5bFJQ65lhdIV9dutS9cp\n"
"LAAuqIKKXe4+UdUFgYa37gTxP4F/qGlsMIt21b33Bm5iyMAwd9uu2RlE29MjqOfN\n"
"FwpBu7/8GgOm+rneKcdS+6DdvOiGFTx+AaPErwShAoGBANoKaRSYvfy3vvBS1MOW\n"
"VnrIxm2n8LFegpNBYXioRMD+QCAp7eADUuUTn6SdVAW8VEKJ+BAVgwtgjNuaouXg\n"
"oqnKNtKqF5RjdfK9x7AVCdRqsOOtDQfILNVZYI1bRYtRzC3YJvZ9Xk/de5irz3ex\n"
"57CG34oXDzvYBZCnFsaN4NmP\n"
"-----END PRIVATE KEY-----\n";
