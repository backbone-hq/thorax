# Thorax Kubernetes Controller

This chart installs a namespaced trust terminator: it verifies encrypted Thorax vault
bytes, decrypts only records covered by the controller identity's current Thorax
authority, and writes only the fields selected by `ThoraxSecret` objects into Kubernetes
`Secret` objects.

The security boundary is intentionally partial. Upstream of projection, Thorax grants,
recipient slots, signatures, and rollback state apply. Downstream, ordinary Kubernetes
RBAC applies. Give each namespace and Thorax vault pair its own identity; do not use one
controller identity across trust boundaries.

## Installation

```sh
helm install thorax-kubernetes-controller \
  ./deploy/charts/thorax-kubernetes-controller \
  --namespace db --create-namespace \
  --set image.digest=sha256:RELEASE_DIGEST
```

Release charts contain the attested release image digest already. An unpackaged source
chart deliberately fails to render without an immutable digest; mutable tags require the
explicit `image.allowMutableTag=true` development escape hatch.

The chart installs cluster-scoped CRDs and a `ValidatingAdmissionPolicy`, but every
runtime object and controller permission is namespaced. Kubernetes 1.31 or newer is
required. The controller never lists or watches core Secrets or ConfigMaps: it fetches
only exact referenced names and asks for metadata alone before touching a projected
Secret. Dynamic object names mean RBAC still has to grant namespaced `get` and mutation
verbs; the admission policy confines controller mutations to Secrets owned by a
`ThoraxSecret` or `ThoraxVault`. Install separate releases in separate namespaces when
plaintext trust boundaries differ. It creates four unbound Roles:

- `*-vault-editor` can declare vault bindings and initiate enrollment.
- `*-secret-editor` can declare projections. This is Secret-writer-equivalent authority.
- `*-approver` can read public join requests and create/delete signed approvals. It
  cannot read or create Kubernetes Secrets.
- `*-publisher` supports `thorax kubernetes publish`: it can get/patch `ThoraxVault`
  objects and get/create/update ConfigMaps. Kubernetes RBAC cannot restrict these verbs
  to the ConfigMap names selected by immutable CR specs, so treat it as namespace-wide
  ConfigMap-writer authority and bind it separately from approval.

Bind those Roles explicitly. The secure chart grants none of them to end users.
Creating or changing a `ThoraxSecret` is Secret-writer-equivalent authority. Its labels
and annotations are copied to the output and may trigger third-party automation, so the
editor Role is not a safe delegation to ordinary application developers.

The runtime image is a static binary in `scratch`, runs as fixed uid/gid 65532 with no
capabilities, a read-only root filesystem, seccomp `RuntimeDefault`, and a one-hour
projected service-account token. The controller has no inbound listener and the chart
denies all ingress. Enable Kubernetes Secret encryption at rest (preferably KMS-backed),
protect etcd backups, and enforce equivalent Pod Security controls for workloads that
consume the resulting plaintext.

## Vault Delivery

The source is a stable, namespaced ConfigMap key. The Thorax CLI can publish the local
encrypted vault directly and wait for the controller to observe the exact revision:

```sh
thorax kubernetes publish payments --namespace db
```

GitOps is an equally valid producer, not a requirement: Argo CD, Flux, CI, Terraform, or
another controller may update the same key. Do not use direct publication and GitOps for
the same ConfigMap unless their ownership and conflict behavior are intentional. The
bytes are encrypted and independently verified; a producer can delay, corrupt, or replay
them, but cannot forge an accepted value.

The selected value must be no larger than 1 MiB. Kubernetes normally enforces the same
object-scale limit, and the controller independently rejects an oversized value rather
than attempting to decode a truncated vault.

```yaml
configMapGenerator:
  - name: thorax-vault-payments
    files:
      - vault.cord=../../.thorax/vault.cord
generatorOptions:
  disableNameSuffixHash: true
```

Create the binding and projections shown in `deploy/examples/kubernetes/`. The
controller generates an immutable identity Secret and a public `ThoraxJoinRequest`.

## Enrollment

From an already trusted Thorax workspace, inspect the request and approve the named
`ThoraxVault` with only the authority you intend to grant. The CLI resolves the exact
request from the vault status and verifies its UID and ownership before signing:

```sh
kubectl -n db get thoraxjoinrequests
thorax kubernetes approve payments \
  --namespace db \
  --read db/prod \
  --yes
thorax kubernetes publish payments --namespace db
```

Omitting `--read` and `--read-exact` grants no access. Suggestions in the request are
review aids only; the granted set and projected set are independent. The CLI confirms
the immutable Kubernetes approval before atomically committing membership, grants, and
all required recipient slots to the local vault. If Kubernetes cannot confirm approval,
the Thorax vault is unchanged. Publish the resulting encrypted `vault.cord` through the
ConfigMap producer. Only the matching approval and published membership together make
the vault Ready.

## Failure and Recovery

`failurePolicy: Delete` and `sourceDeletionPolicy: Delete` are the secure defaults.
Unverifiable input or an authenticated source deletion withdraws the owned Kubernetes
Secret. Set either policy to `Retain` only when availability is worth retaining the last
verified plaintext. Withdrawal is scoped to the Thorax-owned object: a consuming
controller may already have copied the credential or may recreate the same Secret name.
CloudNativePG does the latter for managed roles, under CNPG ownership. Thorax refuses to
adopt that replacement, but removing downstream copies requires the consumer's own
revocation/deletion procedure.

Meaningful condition transitions are also emitted as deduplicated `events.k8s.io/v1`
Events. Status and Events use coarse reasons such as `RollbackSuspected` and
`TrustStateTampered`; they never include plaintext, digests of plaintext, grant details,
or granular cryptographic errors.

Rollback state is stored in a MACed Kubernetes Secret scoped to the trusted root and
identity. If only that state is lost or fails authentication, the controller keeps the
identity, becomes non-Ready, and emits a one-use `RestoreTrust` request. Approve it with
no grants:

```sh
thorax kubernetes approve payments --namespace db --yes
```

RestoreTrust changes no Thorax membership, grants, recipient slots, or vault bytes. The
controller consumes the request and approval after installing the fresh baseline.

If the identity Secret is lost, restore it from backup or explicitly re-enroll: delete
and recreate the `ThoraxVault` so it receives a new UID and identity, then approve with
`--replaces-user OLD_USER`. After the replacement verifies, revoke the old Thorax user
and rotate every affected value. Kubernetes deletion is not revocation, and revocation
alone does not remove recipient slots from old ciphertext; compromise recovery is always
revoke **and** rotate.

## Consumers and Rotation

CloudNativePG consumes a `kubernetes.io/basic-auth` Secret with `username`, `password`,
and `cnpg.io/reload: "true"`; use a managed role, not `bootstrap.initdb.secret`, for
ongoing rotation. Applications can mount the same Secret. Mounted data updates
eventually and must be re-read; environment variables never update in a running pod and
require rollout. Plan retry or dual-role overlap for the controller-to-database rotation
window. This contract was exercised end to end with CloudNativePG 1.30.0: PostgreSQL
accepted the rotated password and rejected the superseded value.
