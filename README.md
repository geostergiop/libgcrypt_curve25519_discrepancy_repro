# Curve25519 toric-discrepancy side-channel lab

This repository contains a completed, source-instrumented reproduction of the
Libgcrypt CVE-2017-0379 Curve25519 leakage predicate. It also contains a
wolfSSL CVE-2025-7396 source-level audit that tests the same kind of
Montgomery/Kummer coordinate predicate in wolfSSL's base-C Curve25519 ladder.

The standard for any future "generalization" example is strict: it must expose
an algebraic discrepancy, divisor, exceptional lifted-coordinate condition, or
clearly isomorphic object that directly drives the leakage label. A generic
timing leak, metadata dispatch bug, variable-time big-integer routine, or
projective-coordinate state leak is not enough by itself.

## Subprojects

```text
subprojects/
  libgcrypt-cve-2017-0379/
    Completed controlled source-instrumented reproduction.
  wolfssl-cve-2025-7396-audit/
    Source-level Curve25519 coordinate-leakage audit for wolfSSL base-C code,
    including instrumentation patch, harness, analyzer, and saved traces.
```

## Research Claim Under Test

The strict CVE-backed claim currently supported by this repository is:

```text
attacker-chosen Curve25519/Kummer input u = +/-1
-> projective Montgomery/Kummer state X = +/-Z
-> implementation path or arithmetic label
-> timing/cache/trace-observable predicate
-> secret-dependent information
```

The discrepancy is not expected to be observed directly. It is a formal way to
name exceptional algebraic states whose implementation consequences can become
observable. The Libgcrypt case is direct because the Curve25519 discrepancy
poles `u = +/-1` correspond to projective Kummer states `X = +/-Z`, and the
historical implementation exposes a short/long reduction label.

The wolfSSL source-level audit shows the same algebraic lift in wolfSSL's
base-C Montgomery ladder:

```text
u = +1 <=> X = Z  -> x_i - z_i == 0
u = -1 <=> X = -Z -> x_i + z_i == 0
```

The subproject includes the source patch that logs these predicates, a harness
that drives `u = 9`, `u = +1`, and `u = -1`, an analyzer, and saved trace
artifacts showing `255/255` scalar-transition matches for the discrepancy-pole
inputs.

Public CVE-2025-7396 material supplies the live side-channel context. wolfSSL
describes the issue as Curve25519 private-key hardening for builds that use the
base-C implementation, not the ARM assembly, Intel assembly, or small
Curve25519 paths. Its advisory says the mitigation is optional hardening
against power or electromagnetic analysis during Curve25519 private-key
operations, reported by Arnaud Varillon, Laurent Sauvage, and Allan Delautre
from Telecom Paris. The patch trail adds `WOLFSSL_CURVE25519_BLINDING` in
5.8.0 and enables it by default for applicable C builds in 5.8.2.

Varillon's 2025 thesis, *Deep Learning for Embedded Cybersecurity*, reports a
profiled EM side-channel evaluation on an STM32F407 Cortex-M4 board, including
wolfSSL. The thesis describes an SLDN attack on a single iteration of wolfSSL
scalar multiplication with enough success to recover the secret scalar. This
supports that CVE-2025-7396 is a real physical side-channel surface in
wolfSSL's Curve25519 scalar multiplication. The artifact here adds the
math-to-code part: for attacker-chosen `u = +/-1`, the same ladder exposes the
lifted-coordinate labels `X = +/-Z`.

Future positive examples must have the same kind of bridge: the algebraic object
must be more than an analogy. It must directly predict the implementation label
that the side channel observes.

## Current status

| Subproject | Status | Question |
| --- | --- | --- |
| `libgcrypt-cve-2017-0379` | Complete artifact | Does `u = +/-1` drive Libgcrypt 1.7.8 into the known leakage predicate? |
| `wolfssl-cve-2025-7396-audit` | Source-level audit | Does wolfSSL's base-C Curve25519 ladder instantiate the same `u = +/-1 -> X = +/-Z` label, and how does that relate to PR #8392's scalar/projective-coordinate blinding? |

## Candidate Review

See `CVE_CANDIDATE_REVIEW.md` for the current triage of candidate CVEs and the
rejection criteria for scalar-multiplication side-channel cases that do not
expose a lifted-coordinate leakage predicate.

## Primary references

- NVD CVE-2017-0379: https://nvd.nist.gov/vuln/detail/CVE-2017-0379
- IACR ePrint 2017/806: https://eprint.iacr.org/2017/806
- NVD CVE-2025-7396: https://nvd.nist.gov/vuln/detail/CVE-2025-7396
- wolfSSL Curve25519 blinding advisory: https://www.wolfssl.com/curve25519-blinding-support-added-in-wolfssl-5-8-0/
- wolfSSL PR #8392: https://github.com/wolfSSL/wolfssl/pull/8392
- wolfSSL PR #8736: https://github.com/wolfSSL/wolfssl/pull/8736
- Varillon thesis record: https://theses.hal.science/tel-05351871v1

## Safety

All experiments in this repository must use generated test keys and isolated
local builds. The goal is source-instrumented reproduction and classification
of leakage predicates, not exploitation of production systems or recovery of
third-party secrets.
