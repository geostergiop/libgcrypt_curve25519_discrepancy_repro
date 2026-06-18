# Curve25519 toric-discrepancy side-channel lab

This repository contains a completed, source-instrumented reproduction of the
Libgcrypt CVE-2017-0379 Curve25519 leakage predicate.

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

Future positive examples must have the same kind of bridge: the algebraic object
must be more than an analogy. It must directly predict the implementation label
that the side channel observes.

## Current status

| Subproject | Status | Question |
| --- | --- | --- |
| `libgcrypt-cve-2017-0379` | Complete artifact | Does `u = +/-1` drive Libgcrypt 1.7.8 into the known leakage predicate? |

## Candidate Review

See `CVE_CANDIDATE_REVIEW.md` for the current triage of candidate CVEs and the
rejection criteria for scalar-multiplication side-channel cases that do not
expose a lifted-coordinate leakage predicate.

## Primary references

- NVD CVE-2017-0379: https://nvd.nist.gov/vuln/detail/CVE-2017-0379
- IACR ePrint 2017/806: https://eprint.iacr.org/2017/806

## Safety

All experiments in this repository must use generated test keys and isolated
local builds. The goal is source-instrumented reproduction and classification
of leakage predicates, not exploitation of production systems or recovery of
third-party secrets.
