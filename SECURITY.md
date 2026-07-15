# Security Policy

Hop is a metadata-privacy mesh messenger: security and privacy are the product, so vulnerability reports
are first-class and we respond quickly.

## Reporting a vulnerability

Please do NOT open a public issue for a security or privacy vulnerability.

Report it privately, in order of preference:

1. **GitHub private vulnerability reporting**: open this repository's **Security** tab and click
   **"Report a vulnerability"**. This keeps the report, the fix, and coordinated disclosure in one place.
2. **Email** `jason@waldrip.net` with the subject prefix `[hop-security]`. If you want an encrypted
   channel, say so in a first low-detail message and we will arrange one.

Please include what the issue is, the impact you believe it has (confidentiality, integrity,
availability, or metadata/traceability), and a proof of concept or the minimal steps to reproduce.

## Scope

This repository is one component of Hop. A report against any Hop component is welcome here; we will
route it and coordinate the fix and disclosure across components as needed.

## Supported versions

Hop is pre-1.0. The supported line is the latest tagged release plus the current `main`; older tags are
not patched, so upgrade to receive fixes.
