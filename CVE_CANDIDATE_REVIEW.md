# CVE Candidate Review For Lifted-Coordinate Scalar-Multiplication Discrepancy

Reviewed on 2026-06-18.

## Scope

This review is no longer limited to Montgomery/Kummer ladders. A positive
candidate may use any scalar multiplication whose implementation works in lifted
coordinates, including:

```text
Montgomery XZ
Kummer or Kummer-surface coordinates
projective or Jacobian Weierstrass coordinates
Lopez-Dahab binary-curve coordinates
extended or inverted Edwards coordinates
Hessian coordinates
genus-0 toric/rational-coordinate lifts
```

The necessary bridge is still strict:

```text
attacker-influenced point, x-coordinate, curve point class, or scalar state
-> scalar multiplication in lifted coordinates
-> exceptional lifted-coordinate predicate or formula label
-> timing/cache/power/EM/source-instrumented observability
-> secret-dependent leakage
```

Examples of acceptable labels include `X = Z`, `X = -Z`, `Z = 0`, identity or
low-order lifted representatives, zero/small multiplication terms, exceptional
addition/doubling formula branches, or reduction/carry labels caused by those
lifted-coordinate terms.

Not enough by itself:

```text
metadata or ASN.1 encoding differences
generic scalar bit-length leakage
compiler-induced field-arithmetic timing without a coordinate predicate
wNAF/table/cache leakage not tied to a lifted-coordinate state
invalid-curve or low-order protocol breaks with only an output oracle
memory safety bugs in X25519/X448 wrappers
```

## Search Terms Used

Searches covered CVEs and open-source/project results after 2012 using:

```text
Curve25519, X25519, X448, Curve448, Montgomery ladder, Kummer,
Kummer surface, scalar multiplication, scalar point multiplication,
projective coordinates, Jacobian coordinates, Lopez-Dahab coordinates,
extended Edwards, inverted Edwards, Hessian coordinates, low-order point,
weak-order point, order-4, twist, invalid curve, off-curve public key,
point x-coordinate, toric, genus 0, algebraic torus, Lucas ladder.
```

## Current Result

Libgcrypt CVE-2017-0379 remains the confirmed CVE-backed instance for the
strict toric/Kummer claim.

No second positive candidate is currently included. A new case should not be
added unless the algebraic object directly predicts the leakage label, not just
because the implementation uses lifted coordinates.

## Confirmed Positive

| Candidate | Status | Reason |
| --- | --- | --- |
| CVE-2017-0379, Libgcrypt Curve25519 | Keep | Direct match. The published attack uses a Curve25519 point of order 4 as chosen ciphertext. Libgcrypt uses Montgomery ladder scalar-by-point multiplication, and the point-at-infinity/order-2/order-4 interactions create side-channel leakage. The local artifact ties this to `u = +/-1 -> X = +/-Z -> short/long reduction label`. |

## Strong Research Candidates For New Tests

These are not CVE-backed confirmations, but they remain useful next tests for a
broader lifted-coordinate discrepancy claim.

| Candidate | Status | Why It Matters |
| --- | --- | --- |
| CVE-2025-7396, wolfSSL Curve25519 C implementation | Active candidate, not confirmed | This is the strongest current CVE candidate because the affected code is X25519/Montgomery-ladder scalar multiplication and the mitigation is Curve25519 blinding. A local formula check using wolfSSL's ladder sequence shows `u = +1` forces `X - Z = 0` labels and `u = -1` forces `X + Z = 0` labels, while the base point does not. The missing proof is whether the reported physical side-channel exploited this discrepancy label rather than generic scalar/value leakage. |
| Hessian, Edwards, and genus-0 toric/rational testbeds | Test candidate | These are useful for mathematical generalization tests. They should be treated as new experiments, not evidence from existing CVEs, unless a concrete implementation exposes a lifted-coordinate label during scalar multiplication. |

## Active Candidate: wolfSSL CVE-2025-7396

Evidence gathered locally:

```text
CVE: CVE-2025-7396
Project: wolfSSL / wolfCrypt
Versions checked:
  v5.8.0-stable commit b077c81eb635392e694ccedbab8b644297ec0285
  v5.8.2-stable commit decea12e223869c8f8f3ab5a53dc90b69f436eb2
```

The public CVE says wolfSSL 5.8.2 turns on blinding support by default for the
base C Curve25519 implementation in applicable builds, as additional protection
for physical side-channel observation. wolfSSL's advisory says 5.8.0 added
optional blinding and that future releases would enable it by default. The
configuration class of interest is therefore unblinded base-C Curve25519 private
key scalar multiplication, not every wolfSSL build. The affected APIs listed by
the advisory include:

```text
wc_curve25519_export_public_ex
wc_curve25519_make_key
wc_curve25519_generic
wc_curve25519_shared_secret_ex
```

The relevant source bridge is concrete:

```text
wolfcrypt/src/curve25519.c
  wc_curve25519_shared_secret_ex
    without WOLFSSL_CURVE25519_BLINDING:
      curve25519(o.point, private_key->k, public_key->p.point)
    with WOLFSSL_CURVE25519_BLINDING:
      curve25519_smul_blind(...)

wolfcrypt/src/fe_operations.c
  curve25519(...)
    Montgomery XZ ladder with x2,z2,x3,z3

wolfssl/wolfcrypt/settings.h in 5.8.2
  defines WOLFSSL_CURVE25519_BLINDING by default for C-only, non-small
  Curve25519 builds unless explicitly disabled.
```

The local algebraic check mirrors wolfSSL's ladder formulas over
`p = 2^255 - 19`:

```text
basepoint u = 9:
  no X +/- Z zero labels in the checked ladder steps

u = +1:
  repeated X - Z = 0 labels

u = -1:
  repeated X + Z = 0 labels
```

That is the same kind of discrepancy bridge as the Libgcrypt artifact at the
math/source level:

```text
Curve25519 discrepancy pole u = +/-1
-> Montgomery XZ lifted state X = +/-Z
-> zero input to field subtraction/squaring/multiplication sites
-> physically plausible DPA/EM value label
```

Current classification: active candidate, not confirmed positive.

Reason for caution: the public wolfSSL CVE/advisory does not say the reported
side-channel attack used attacker-chosen low-order inputs or the `X = +/-Z`
label. It may be generic unblinded scalar/value leakage. This candidate should
only become a positive subproject after source instrumentation verifies that
the label is stable, scalar-correlated, and affected by the 5.8.2 blinding path.

## CVE Near Misses

The key distinction is: using lifted coordinates is necessary for this
generalization, but it is not sufficient. The CVE must also leak a label caused
by the lifted-coordinate state.

| CVE | Project | Lifted-coordinate use? | Classification | Reason |
| --- | --- | --- | --- | --- |
| CVE-2018-20187 | Botan | Yes: Botan `PointGFp` stores `x,y,z` and scalar multiplication updates projective/Jacobian-style state. | Scalar-multiplication timing near miss | The CVE is about unblinded scalar multiplication during ECC key generation. No public source ties the leakage to a predicate such as `Z = 0` or a zero/small formula term. |
| CVE-2019-13628 | wolfSSL/wolfCrypt | Yes: wolfCrypt ECC uses Jacobian projective point addition/doubling and `ecc_point` with `x,y,z`. | Scalar-multiplication timing near miss | Public description says `ecc.c` scalar multiplication may leak bit length. No lifted-coordinate leakage label is specified. |
| CVE-2019-13629 | MatrixSSL | Unknown from public source checked here. | Scalar-multiplication timing near miss | Public description says scalar multiplication leaks scalar bit length. I did not find a reliable public source snapshot proving its coordinate representation, so this must not be used as coordinate evidence yet. |
| CVE-2019-15809 | Athena / Atmel Toolbox | Unknown; closed/vendor implementation details are not public in the CVE record. | Scalar-multiplication timing near miss | ECDSA signing leaks nonce bit length through timing. This is scalar leakage, but not currently a coordinate-lift predicate. |
| CVE-2019-16863 | STMicroelectronics TPM-FAIL | Unknown; closed TPM implementation details are not public in the CVE record. | Scalar-multiplication timing near miss | ECDSA scalar multiplication is mishandled and leaks through timing. The public CVE record does not identify a lifted-coordinate predicate. |
| CVE-2019-11090 | Intel PTT/TXE/SPS | Unknown; firmware implementation details are not public in the CVE record. | Timing near miss | Cryptographic timing issue related to TPM-FAIL context, but public NVD text is too general to support a coordinate-lift claim. |
| CVE-2024-50383 | Botan X25519 | Yes at the algorithm level: X25519 uses Montgomery `x`-coordinate scalar multiplication; this CVE targets Botan's `donna128` arithmetic path. | X25519 field-arithmetic near miss | Compiler-induced skipped addition in `donna128` is relevant to X25519 side channels, but the label is a carry/compiler artifact, not a coordinate-lift predicate. |
| CVE-2025-12888 | wolfSSL X25519 | Yes: wolfSSL's X25519 code uses Montgomery ladder state with `x1,x2,z2,x3,z3`. | X25519 implementation near miss | Timing side channels come from compiler optimization and Xtensa CPU limitations. No lifted-coordinate predicate is documented. |
| CVE-2025-3301 | Silicon Labs Curve25519/Curve448 | Algorithmically yes for Curve25519/Curve448 ECDH, which are x-coordinate Montgomery-ladder operations; public implementation details are sparse. | Physical side-channel near miss | DPA countermeasures are unavailable for Curve25519/Curve448 ECDH and EdDSA. Important, but too broad to support a coordinate-lift discrepancy without new traces or source analysis. |
| CVE-2024-58262 | curve25519-dalek | No for the vulnerability site. The library has point-coordinate machinery, but this CVE is about scalar constant-time code removed by LLVM. | Compiler/constant-time near miss | The public issue is scalar-only constant-time failure, not a point-coordinate lift predicate. |

## Rejected As Out Of Scope

| CVE | Reason |
| --- | --- |
| CVE-2016-6878, Botan Curve25519 | Undefined behavior in Curve25519 code on systems without native 128-bit integers. No side-channel coordinate predicate. |
| CVE-2022-29245, SSH.NET X25519 | Weak RNG for X25519 private key generation. Not a coordinate-lift or side-channel predicate. |
| CVE-2026-41676, rust-openssl X25519/X448 | Buffer overflow in derive wrapper for short output slices. Not a scalar-multiplication leakage predicate. |

## Test Guidance

Do not add a new positive subproject unless it can instrument this chain:

```text
input/scalar condition
-> lifted-coordinate scalar-multiplication state or formula term
-> stable implementation label
-> externally plausible timing/cache/power/EM observation
-> recoverable secret-dependent information
```

For the next useful tests, prioritize:

```text
1. Instrument projective/Jacobian scalar multiplication formulas and label
   exceptional terms such as Z=0, denominator-equivalent zero terms, identity
   representatives, and zero/small products.
2. Only then map a CVE to the discrepancy framework if the observed label is
   caused by the lifted-coordinate state, not merely by scalar bit length.
```

## Sources Checked

- NVD CVE-2017-0379: https://nvd.nist.gov/vuln/detail/CVE-2017-0379
- IACR ePrint 2017/806: https://eprint.iacr.org/2017/806
- NVD CVE-2018-20187: https://nvd.nist.gov/vuln/detail/CVE-2018-20187
- Botan 2.8.0 `point_gfp.cpp`: https://raw.githubusercontent.com/randombit/botan/2.8.0/src/lib/pubkey/ec_group/point_gfp.cpp
- NVD CVE-2019-13628: https://nvd.nist.gov/vuln/detail/CVE-2019-13628
- wolfSSL 4.0.0 `ecc.c`: https://raw.githubusercontent.com/wolfSSL/wolfssl/v4.0.0-stable/wolfcrypt/src/ecc.c
- NVD CVE-2019-13629: https://nvd.nist.gov/vuln/detail/CVE-2019-13629
- NVD CVE-2019-15809: https://nvd.nist.gov/vuln/detail/CVE-2019-15809
- NVD CVE-2019-16863: https://nvd.nist.gov/vuln/detail/CVE-2019-16863
- NVD CVE-2019-11090: https://nvd.nist.gov/vuln/detail/CVE-2019-11090
- NVD CVE-2024-50383: https://nvd.nist.gov/vuln/detail/CVE-2024-50383
- NVD CVE-2025-12888: https://nvd.nist.gov/vuln/detail/CVE-2025-12888
- NVD CVE-2025-3301: https://nvd.nist.gov/vuln/detail/CVE-2025-3301
- NVD CVE-2025-7396: https://nvd.nist.gov/vuln/detail/CVE-2025-7396
- wolfSSL Curve25519 blinding advisory: https://www.wolfssl.com/curve25519-blinding-support-added-in-wolfssl-5-8-0/
- wolfSSL ChangeLog CVE-2025-7396 entry: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md
- wolfSSL 5.8.2 `fe_operations.c`: https://raw.githubusercontent.com/wolfSSL/wolfssl/v5.8.2-stable/wolfcrypt/src/fe_operations.c
- wolfSSL 5.8.2 `fe_x25519_128.h`: https://raw.githubusercontent.com/wolfSSL/wolfssl/v5.8.2-stable/wolfcrypt/src/fe_x25519_128.h
- wolfSSL 5.8.2 `fe_448.c`: https://raw.githubusercontent.com/wolfSSL/wolfssl/v5.8.2-stable/wolfcrypt/src/fe_448.c
- NVD CVE-2024-58262: https://nvd.nist.gov/vuln/detail/CVE-2024-58262
- NVD CVE-2016-6878: https://nvd.nist.gov/vuln/detail/CVE-2016-6878
- NVD CVE-2022-29245: https://nvd.nist.gov/vuln/detail/CVE-2022-29245
- NVD CVE-2026-41676: https://nvd.nist.gov/vuln/detail/CVE-2026-41676
