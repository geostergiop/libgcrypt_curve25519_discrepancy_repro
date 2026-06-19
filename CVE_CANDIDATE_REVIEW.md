# CVE Candidate Review For Lifted-Coordinate Scalar-Multiplication Discrepancy

Reviewed on 2026-06-19.

## Scope

A positive example must use scalar multiplication whose implementation works in
lifted coordinates and must expose a leakage label caused by an exceptional
lifted-coordinate predicate. The current positive Montgomery examples use XZ
coordinates, but the same review rule also covers Kummer surfaces, projective or
Jacobian Weierstrass coordinates, Lopez-Dahab binary-curve coordinates,
extended/inverted Edwards coordinates, Hessian coordinates, and genus-0
toric/rational-coordinate lifts.

Required bridge:

```text
attacker-influenced point, x-coordinate, point class, or scalar state
-> scalar multiplication in lifted coordinates
-> exceptional lifted-coordinate predicate or formula label
-> timing/cache/power/EM/source-instrumented observability
-> secret-dependent leakage
```

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

Libgcrypt CVE-2017-0379 remains the confirmed attack instance. The published
attack uses order-4 Curve25519 inputs, and this repository ties those inputs to:

```text
u = +/-1 -> X = +/-Z -> short/long reduction label
```

wolfSSL CVE-2025-7396 is a confirmed implementation instance. Public
CVE/advisory material establishes a physical side-channel hardening surface for
wolfSSL's base-C Curve25519 scalar multiplication. The local artifact confirms
that the same base-C ladder instantiates:

```text
u = +/-1 -> X = +/-Z -> operation-local zero/Hamming-weight label
```

The exact `255/255` scalar-transition result is for the unblinded wolfSSL
schedule in a source/model-level EM leakage model. For wolfSSL's blinded/default
path, the supported statement is divisor invariance under coordinate scaling and
scalar-mask consistency, not that the public CVE trace used the same simple
unblinded classifier.

## Implementation Instances

| Candidate | Status | Reason |
| --- | --- | --- |
| CVE-2017-0379, Libgcrypt Curve25519 | Confirmed attack instance of algebraic discrepancy | Direct match. The published attack uses a Curve25519 point of order 4 as chosen ciphertext. Libgcrypt uses Montgomery ladder scalar-by-point multiplication. The local artifact ties `u = +/-1` to `X = +/-Z` and then to a short/long reduction label inside Libgcrypt 1.7.8. |
| CVE-2025-7396, wolfSSL Curve25519 C implementation | Confirmed implementation instance of algebraic discrepancy | Public CVE/advisory material confirms a physical side-channel hardening surface in wolfSSL's base-C Curve25519 scalar multiplication. Local source/model instrumentation confirms that `u = +1` and `u = -1` force `X = +/-Z` labels in wolfSSL's base-C Montgomery ladder. In the unblinded schedule, operation-local zero/HW windows match the adjacent scalar-transition label `255/255`. |

## Local Audit: wolfSSL CVE-2025-7396

Evidence gathered locally:

```text
CVE: CVE-2025-7396
Project: wolfSSL / wolfCrypt
Versions checked:
  v5.8.0-stable commit b077c81eb635392e694ccedbab8b644297ec0285
  v5.8.2-stable commit decea12e223869c8f8f3ab5a53dc90b69f436eb2
```

Public source boundary:

```text
NVD/GHSA:
  wolfSSL 5.8.2 turns Curve25519 blinding on by default for applicable builds.
  The option is only for the base-C Curve25519 implementation.
  ARM assembly, Intel assembly, and small Curve25519 builds are excluded.
  The attack vector is physical.

wolfSSL advisory:
  wolfSSL 5.8.0 added optional hardening against power or EM analysis during
  Curve25519 private-key operations.
  Affected APIs include wc_curve25519_export_public_ex,
  wc_curve25519_make_key, wc_curve25519_generic, and
  wc_curve25519_shared_secret_ex.

PR #8392:
  adds Curve25519 blinding for private-key use.
  The PR body says it XORs a random value into the scalar and performs special
  scalar multiplication.
  The merged commit message says it multiplies x3 and z3 by a random value to
  randomize coordinates.

PR #8736:
  adjusts the default Curve25519 build so applicable C builds use the blinding.
```

The relevant source bridge is:

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
```

The local source instrumentation mirrors wolfSSL's ladder formulas over
`p = 2^255 - 19`:

```text
basepoint u = 9:
  no X +/- Z zero labels in the checked ladder steps

u = +1:
  repeated X - Z = 0 labels at fixed ladder formula sites

u = -1:
  repeated X + Z = 0 labels at fixed ladder formula sites
```

The latest symbolic/source-model result is:

```text
u = +1:
  exactly one relevant x2/x3 zero each step: 255/255
  x2-zero label matches unblinded cswap transition: 255/255
  aggregate sumHW: 433771
  zero outputs: 1147

u = -1:
  exactly one relevant x2/x3 zero each step: 255/255
  x2-zero label matches unblinded cswap transition: 255/255
  aggregate sumHW: 437482
  zero outputs: 1147

generic u = 9:
  relevant pole zero slots: 0
  aggregate sumHW: 581379
  zero outputs: 0
```

Interpretation:

```text
Curve25519 discrepancy pole u = +/-1
-> Montgomery XZ lifted state X = +/-Z
-> zero input/output at fixed field-operation windows
-> operation-local Hamming-weight/register-zero label
-> physically plausible EM/power template target
```

The aggregate Hamming-weight intervals overlap, so the artifact does not claim a
perfect whole-function HW classifier. The clean label is operation-local.

## Remaining Research Candidates

These are useful source-level tests for a broader lifted-coordinate discrepancy
claim.

| Candidate | Status | Why It Matters |
| --- | --- | --- |
| Hessian, Edwards, and genus-0 toric/rational testbeds | Test candidate | Useful mathematical generalization tests where the experiment can directly instrument lifted-coordinate labels during scalar multiplication. |

## CVE Near Misses

Using lifted coordinates is necessary for this generalization, but it is not
sufficient. The CVE must also leak a label caused by the lifted-coordinate
state.

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
- CVEAWG CVE-2025-7396 record: https://cveawg.mitre.org/api/cve/CVE-2025-7396
- GitHub Advisory GHSA-h9v3-wvxh-4mwp: https://github.com/advisories/GHSA-h9v3-wvxh-4mwp
- OSV CVE-2025-7396: https://api.osv.dev/v1/vulns/CVE-2025-7396
- wolfSSL Curve25519 blinding advisory: https://www.wolfssl.com/curve25519-blinding-support-added-in-wolfssl-5-8-0/
- wolfSSL security vulnerabilities page: https://www.wolfssl.com/docs/security-vulnerabilities/
- wolfSSL ChangeLog CVE-2025-7396 entry: https://github.com/wolfSSL/wolfssl/blob/master/ChangeLog.md
- wolfSSL PR #8392: https://github.com/wolfSSL/wolfssl/pull/8392
- wolfSSL PR #8736: https://github.com/wolfSSL/wolfssl/pull/8736
- wolfSSL issue #10587: https://github.com/wolfSSL/wolfssl/issues/10587
- wolfSSL 5.8.2 `fe_operations.c`: https://raw.githubusercontent.com/wolfSSL/wolfssl/v5.8.2-stable/wolfcrypt/src/fe_operations.c
- wolfSSL 5.8.2 `fe_x25519_128.h`: https://raw.githubusercontent.com/wolfSSL/wolfssl/v5.8.2-stable/wolfcrypt/src/fe_x25519_128.h
- wolfSSL 5.8.2 `fe_448.c`: https://raw.githubusercontent.com/wolfSSL/wolfssl/v5.8.2-stable/wolfcrypt/src/fe_448.c
- NVD CVE-2024-58262: https://nvd.nist.gov/vuln/detail/CVE-2024-58262
- NVD CVE-2016-6878: https://nvd.nist.gov/vuln/detail/CVE-2016-6878
- NVD CVE-2022-29245: https://nvd.nist.gov/vuln/detail/CVE-2022-29245
- NVD CVE-2026-41676: https://nvd.nist.gov/vuln/detail/CVE-2026-41676
