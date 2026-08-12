# Security Policy

Thorax handles secret values, private identities, authorization state, and signed release artifacts. Security reports are treated as confidential until a fix and coordinated disclosure are ready.

The project [threat model](./README.md#threat-model) and [security properties](./README.md#security-properties) define the guarantees and limitations in scope.

## Supported Versions

Security fixes are produced for the latest stable Thorax release. Earlier releases receive a backport only when the corresponding advisory explicitly identifies them as supported. Unreleased development revisions do not receive security backports, although reports against them are welcome.

| Release | Security support |
|---|---|
| Latest stable release | Supported |
| Earlier stable releases | Only when stated in an advisory |
| Unreleased development revisions | Not supported |

Users should update to the latest signed release when a security fix becomes available.

## Public Security Assurance

Thorax publishes the evidence behind its security claims:

- The [threat model](./README.md#threat-model) identifies protected assets, attacker capabilities, trusted boundaries, and explicit limitations
- The [security properties](./README.md#security-properties) describe the cryptographic and fail-closed behavior implemented by Thorax
- The public [CI workflow](./.github/workflows/ci.yml) runs workspace tests, Clippy with warnings denied, documentation checks, RustSec advisory checks, generated-CRD verification, Helm linting, static security invariants, and Kubernetes acceptance tests
- The public [Kubernetes security checks](./deploy/tests/security-static.sh) verify controller packaging, workload hardening, RBAC, admission policy, and release-workflow invariants
- The [verified distribution process](./README.md#verified-distribution) authenticates release manifests and artifacts and rejects replay of an older signed release after newer trust has been established

These controls provide reviewable evidence and regression coverage. They do not establish that the software is free from vulnerabilities.

## Reporting a Vulnerability

Do not report suspected vulnerabilities through public GitHub issues, pull requests, discussions, or other public channels.

Send reports to [root@backbone.dev](mailto:root@backbone.dev). If you are unsure whether a finding is security-sensitive, report it privately.

## Encrypted Reports

Sensitive reports may be encrypted with the Thorax security reporting public key below. Verify the complete fingerprint before use.

<!-- BEGIN OPENPGP REPORTING KEY -->

Identity: `Backbone Security <root@backbone.dev>`

Expires: `2028-08-11`

Fingerprint:

```text
56C3 AEE5 7D9C 779F F51F 7981 D307 5048 2992 D9CD
```

Public key:

```text
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEanz+URYJKwYBBAHaRw8BAQdAIsXDMe8IpdVMCSzjir3JMHSBTAdf4bY5sHZ1
/1INPwm0JUJhY2tib25lIFNlY3VyaXR5IDxyb290QGJhY2tib25lLmRldj6ImQQT
FgoAQRYhBFbDruV9nHef9R95gdMHUEgpktnNBQJqfP5RAhsBBQkDwmcABQsJCAcC
AiICBhUKCQgLAgQWAgMBAh4HAheAAAoJENMHUEgpktnNqHQA/i2BBs2pN0F5OjXx
iHoqn0EFteQTTgmuMzUPhJYZvrsyAQC0EYDMXyW5/vcgebaGUE8h61Fb8cOvOiGr
QmBBHqfwDrg4BGp8/lESCisGAQQBl1UBBQEBB0CI0NDShkmCj2CpxxFSJR2EyMCF
neCIvZWnCCROsMjFCQMBCAeIfgQYFgoAJhYhBFbDruV9nHef9R95gdMHUEgpktnN
BQJqfP5RAhsMBQkDwmcAAAoJENMHUEgpktnNfUgA/13yBSJ52g4V4P1GQOhmNMSu
tzP729AK8FEDfxH8TW6/AP4mHXh+NdyhWaFXv95NbWF0shhPq8sCkrS22A31ZQlc
DQ==
=0dC6
-----END PGP PUBLIC KEY BLOCK-----
```

<!-- END OPENPGP REPORTING KEY -->

Send the encrypted report to [root@backbone.dev](mailto:root@backbone.dev).

OpenPGP encryption protects the report body and encrypted attachments. It does not conceal email metadata such as the sender, recipient, subject, or delivery time. This reporting key is separate from the Thorax release verification key and must not be used to verify releases.

The reporting key will be replaced before it expires. If it is revoked or suspected to be compromised, this policy will publish the replacement key and fingerprint. Verify the key against the current policy before every use.

Include the following information when available:

- The affected Thorax version, platform, and interface
- The security impact and the attacker capabilities required
- Reproduction steps or a minimal proof of concept
- Relevant logs, error messages, stack traces, or screenshots
- Any known mitigations or conditions that prevent exploitation

Remove secret values, invite capabilities, private identity material, credentials, and unrelated personal data from reports. Do not send a real vault or identity seed unless Backbone requests it through an agreed secure channel.

Reports concerning unauthorized plaintext access, forged authority, signature or rollback verification, identity handling, release verification, and Kubernetes trust boundaries are particularly useful. Availability and metadata findings are also welcome when they cross the guarantees stated in the threat model.

## Safe Harbor

Backbone considers security research conducted under this policy to be authorized when the researcher:

- Acts in good faith to identify and report a vulnerability
- Avoids privacy violations, unnecessary data access, service degradation, persistence, social engineering, physical intrusion, and modification of data that is not required to demonstrate the finding
- Uses test accounts, test vaults, and synthetic secret values whenever possible
- Accesses only the minimum data necessary to establish impact, stops when sensitive or third-party data is encountered, and reports the exposure promptly
- Does not exploit a vulnerability beyond what is necessary to confirm it
- Follows the coordinated disclosure process and does not use the finding for extortion or commercial leverage

Backbone will not initiate legal action or request a Digital Millennium Copyright Act investigation for research that complies with this policy. If a third party initiates legal action arising from compliant research, Backbone will make the researcher's compliance with this policy known where it is able to do so.

This safe harbor does not authorize research against third-party systems, access to third-party data, or conduct prohibited by applicable law. Contact [root@backbone.dev](mailto:root@backbone.dev) before proceeding if the scope or likely impact is unclear.

## Response Commitments

Backbone will:

- Acknowledge a report within two business days
- Provide an initial assessment within five business days
- Provide a remediation or containment plan within three business days after confirming a critical vulnerability
- Send a status update at least once every seven calendar days while an accepted report remains unresolved

The initial assessment will state whether the report is accepted, requires more information, or falls outside the documented security guarantees. If a deadline cannot be met, Backbone will notify the reporter before it expires and provide a revised date.

## Coordinated Disclosure

Backbone will investigate accepted reports, prepare remediation, and coordinate disclosure with the reporter. After a fixed release becomes available, the normal public disclosure window is 7 days for critical vulnerabilities and 14 days for non-critical vulnerabilities. These windows allow users to adopt the fix without delaying public notice unnecessarily.

Disclosure timing may change when exploitation is active, a safe fix requires broader coordination, or early publication would materially increase risk. Credit is given with the reporter's permission.

## Security Advisories

A confirmed vulnerability affecting a released version will be documented in a [GitHub Security Advisory](https://github.com/backbone-hq/thorax/security/advisories) and the corresponding release notes. The advisory will identify affected versions, severity, impact, available mitigations, the fixed version, and reporter credit when permission is given.

Advisories are normally published after a fixed release is available and the coordinated disclosure window has elapsed. Backbone may publish earlier when exploitation is active or immediate disclosure materially reduces user risk. Material corrections will be added to the advisory record.
