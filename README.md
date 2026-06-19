# Curve25519 Toric-Discrepancy Side-Channel Lab

This repository contains source-level experiments connecting the Montgomery
toric discrepancy poles on Curve25519 to concrete implementation leakage
labels.

The repository currently has two implementation instances:

```text
libgcrypt-cve-2017-0379
  Confirmed attack instance. The historical Libgcrypt 1.7.8 attack observes a
  short/long reduction label reached by attacker-controlled order-4 inputs.

wolfssl-cve-2025-7396-audit
  Confirmed implementation instance. The wolfSSL base-C Curve25519 ladder
  reaches the same discrepancy-pole coordinate state; in a source/model-level
  EM leakage model, operation-local zero/Hamming-weight windows carry the
  unblinded scalar-transition label.
```

The standard for future examples is strict. A positive example must expose an
algebraic discrepancy, divisor, exceptional lifted-coordinate condition, or
clearly isomorphic object that directly drives the leakage label. A generic
timing leak, metadata dispatch bug, variable-time big-integer routine, or
projective-coordinate state leak is not enough by itself.

## Subprojects

```text
subprojects/
  libgcrypt-cve-2017-0379/
    Controlled source-instrumented reproduction for Libgcrypt 1.7.8.

  wolfssl-cve-2025-7396-audit/
    Source/model-level Curve25519 coordinate-leakage audit for wolfSSL base-C
    code, including instrumentation patch, harness, analyzer, saved traces, and
    symbolic Hamming-weight experiments.
```

## Research Claim Under Test

The shared algebraic chain is:

```text
attacker-chosen Curve25519/Kummer input u = +/-1
-> projective Montgomery/Kummer state X = +/-Z
-> zero-valued lifted-coordinate formula term
-> implementation-specific observable label
-> secret-dependent information
```

The discrepancy is not observed directly. It is a formal way to name
exceptional algebraic states whose implementation consequences can become
observable.

In Libgcrypt 1.7.8, the zero/small formula state reaches variable-length MPI
reduction behavior. The observable label is a short/long reduction path.

In wolfSSL's base-C Curve25519 ladder, the same pole lifts to:

```text
u = +1 <=> X = Z  -> x_i - z_i == 0
u = -1 <=> X = -Z -> x_i + z_i == 0
```

The wolfSSL artifact is explicitly source/model-level. It does not claim an
external EM trace of a compiled wolfSSL binary. It shows that the vulnerable
unblinded base-C ladder has the discrepancy-pole implementation state and that
operation-local zero/Hamming-weight windows can carry the adjacent scalar
transition label. The exact `255/255` transition-label result is for the
unblinded schedule. For the blinded/default path, the repository claims
coordinate-level divisor invariance and scalar-mask consistency, not that the
public CVE trace used this exact classifier.

## wolfSSL Result Snapshot

The latest symbolic experiment gives:

```text
generic u = 9:
  relevant pole zero slots: 0
  aggregate sumHW: 581379
  zero outputs: 0

u = +1:
  exactly one relevant x2/x3 pole zero each step: 255/255
  x2-zero label matches the unblinded cswap transition: 255/255
  aggregate sumHW: 433771
  zero outputs: 1147

u = -1:
  exactly one relevant x2/x3 pole zero each step: 255/255
  x2-zero label matches the unblinded cswap transition: 255/255
  aggregate sumHW: 437482
  zero outputs: 1147
```

The aggregate Hamming-weight intervals overlap, so a coarse whole-function HW
sum is not by itself a perfect classifier. The clean label is operation-local:
specific subtraction/addition windows and their dependent products are zero
exactly on one transition class in the source model.

## Implementation Instances

| Subproject | Status | Evidence |
| --- | --- | --- |
| `libgcrypt-cve-2017-0379` | Confirmed attack instance of algebraic discrepancy | The historical CVE attack uses attacker-controlled order-4 Curve25519 inputs. The artifact ties those inputs to `u = +/-1 -> X = +/-Z -> short/long reduction label` inside Libgcrypt 1.7.8. |
| `wolfssl-cve-2025-7396-audit` | Confirmed implementation instance of algebraic discrepancy | Public CVE/advisory material establishes a physical side-channel hardening surface for wolfSSL base-C Curve25519. The artifact confirms that attacker-controlled `u = +/-1` reaches `X = +/-Z`; in the unblinded source/model schedule, operation-local zero/HW windows carry the scalar-transition label `255/255`. |

## Candidate Review

See `CVE_CANDIDATE_REVIEW.md` for implementation instances, near misses, and
rejection criteria for scalar-multiplication side-channel cases that do not
expose a lifted-coordinate leakage predicate.

## Primary References

- NVD CVE-2017-0379: https://nvd.nist.gov/vuln/detail/CVE-2017-0379
- IACR ePrint 2017/806: https://eprint.iacr.org/2017/806
- NVD CVE-2025-7396: https://nvd.nist.gov/vuln/detail/CVE-2025-7396
- GitHub Advisory GHSA-h9v3-wvxh-4mwp: https://github.com/advisories/GHSA-h9v3-wvxh-4mwp
- wolfSSL Curve25519 blinding advisory: https://www.wolfssl.com/curve25519-blinding-support-added-in-wolfssl-5-8-0/
- wolfSSL PR #8392: https://github.com/wolfSSL/wolfssl/pull/8392
- wolfSSL PR #8736: https://github.com/wolfSSL/wolfssl/pull/8736
- Varillon thesis record: https://theses.hal.science/tel-05351871v1

## Safety

All experiments use generated test keys and isolated local builds. The goal is
source-instrumented reproduction and classification of leakage predicates, not
exploitation of production systems or recovery of third-party secrets.
