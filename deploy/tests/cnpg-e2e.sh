#!/usr/bin/env bash
set -euo pipefail

: "${KUBECONFIG:?set KUBECONFIG to the intended cluster}"
: "${THORAX_E2E_NAMESPACE:?set a unique test namespace}"

thorax_crds=(
  thoraxjoinapprovals.thorax.backbone.dev
  thoraxjoinrequests.thorax.backbone.dev
  thoraxsecrets.thorax.backbone.dev
  thoraxvaults.thorax.backbone.dev
)

thorax_e2e_preflight() {
  [[ "${THORAX_E2E_DISPOSABLE_CLUSTER:-no}" == yes ]] || {
    echo "the public acceptance test runs only against an explicitly disposable cluster" >&2
    exit 2
  }
  [[ "$THORAX_E2E_NAMESPACE" == thorax-e2e-* ]] || {
    echo "THORAX_E2E_NAMESPACE must begin with thorax-e2e-" >&2
    exit 2
  }
}

thorax_e2e_cleanup_environment() {
  KUBECONFIG="$KUBECONFIG" kubectl delete namespace "$THORAX_E2E_NAMESPACE" \
    --wait=false >/dev/null 2>&1 || true
}

thorax_e2e_prepare_cnpg() {
  cnpg_manifest="$scratch/cnpg.yaml"
  curl -fsSL --retry 3 -o "$cnpg_manifest" \
    "https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v${cnpg_version}/cnpg-${cnpg_version}.yaml"
  printf '%s  %s\n' "$cnpg_sha256" "$cnpg_manifest" | sha256sum --check --status
  sed -i \
    "s|ghcr.io/cloudnative-pg/cloudnative-pg:${cnpg_version}|ghcr.io/cloudnative-pg/cloudnative-pg@${cnpg_controller_digest}|" \
    "$cnpg_manifest"
  grep -Fq "ghcr.io/cloudnative-pg/cloudnative-pg@${cnpg_controller_digest}" "$cnpg_manifest"

  kubectl apply --server-side -f "$cnpg_manifest"
  kubectl rollout status deployment/cnpg-controller-manager -n cnpg-system --timeout=240s
}

thorax_e2e_verify_environment() {
  :
}

if [[ -n "${THORAX_E2E_DRIVER:-}" ]]; then
  [[ "$THORAX_E2E_DRIVER" == /* && -f "$THORAX_E2E_DRIVER" ]] || {
    echo "THORAX_E2E_DRIVER must name an absolute regular file" >&2
    exit 2
  }
  # An environment-specific driver may replace the four lifecycle functions.
  # Such drivers are operational material and are not part of the public test.
  source "$THORAX_E2E_DRIVER"
fi
for hook in \
  thorax_e2e_preflight \
  thorax_e2e_cleanup_environment \
  thorax_e2e_prepare_cnpg \
  thorax_e2e_verify_environment; do
  declare -F "$hook" >/dev/null || { echo "test driver lacks $hook" >&2; exit 2; }
done

for command in kubectl helm jq curl sha256sum cargo; do
  command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
scratch=$(mktemp -d /tmp/thorax-cnpg-acceptance.XXXXXX)
controller_pid=""
thorax_e2e_preflight
cleanup() {
  local exit_status=$?
  if [[ -n "$controller_pid" ]]; then
    kill "$controller_pid" 2>/dev/null || true
    wait "$controller_pid" 2>/dev/null || true
  fi
  if [[ "$exit_status" -ne 0 && -s "$scratch/controller.log" ]]; then
    echo "Thorax controller log after acceptance-test failure:" >&2
    sed 's/^/  /' "$scratch/controller.log" >&2
  fi
  KUBECONFIG="$KUBECONFIG" helm uninstall thorax-e2e -n "$THORAX_E2E_NAMESPACE" >/dev/null 2>&1 || true
  thorax_e2e_cleanup_environment
  rm -rf -- "$scratch"
  return "$exit_status"
}
trap cleanup EXIT

cd "$repo_root"

cnpg_version=1.30.0
cnpg_sha256=f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88
cnpg_controller_digest=sha256:091d306935cfdf646debfe78010d59ebfb572150eb6eb922b0203873c0c68841
thorax_e2e_prepare_cnpg

controller_repository=${THORAX_E2E_CONTROLLER_REPOSITORY:-}
controller_tag=${THORAX_E2E_CONTROLLER_TAG:-}
if [[ -n "$controller_repository" || -n "$controller_tag" ]]; then
  [[ -n "$controller_repository" && -n "$controller_tag" ]] || {
    echo "set both THORAX_E2E_CONTROLLER_REPOSITORY and THORAX_E2E_CONTROLLER_TAG" >&2
    exit 2
  }
  helm install thorax-e2e deploy/charts/thorax-kubernetes-controller \
    --namespace "$THORAX_E2E_NAMESPACE" --create-namespace \
    --set replicaCount=1 \
    --set image.repository="$controller_repository" \
    --set image.tag="$controller_tag" \
    --set image.allowMutableTag=true \
    --set image.pullPolicy=Never
  cargo build --locked -p thorax
  kubectl -n "$THORAX_E2E_NAMESPACE" rollout status \
    deployment/thorax-e2e-thorax-kubernetes-controller --timeout=240s
  expected_holder=$(kubectl -n "$THORAX_E2E_NAMESPACE" get pod \
    -l app.kubernetes.io/name=thorax-kubernetes-controller \
    -o jsonpath='{.items[0].metadata.name}')
else
  helm install thorax-e2e deploy/charts/thorax-kubernetes-controller \
    --namespace "$THORAX_E2E_NAMESPACE" --create-namespace --set replicaCount=0 \
    --set image.allowMutableTag=true
  cargo build --locked -p thorax -p thorax-kubernetes-controller

  service_account=thorax-e2e-thorax-kubernetes-controller
  token=$(kubectl -n "$THORAX_E2E_NAMESPACE" create token "$service_account" --duration=30m)
  server=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
  ca_data=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
  printf '%s' "$ca_data" | base64 -d > "$scratch/ca.crt"
  kubectl config --kubeconfig="$scratch/controller.kubeconfig" set-cluster e2e \
    --server="$server" --certificate-authority="$scratch/ca.crt" --embed-certs=true >/dev/null
  kubectl config --kubeconfig="$scratch/controller.kubeconfig" set-credentials controller --token="$token" >/dev/null
  kubectl config --kubeconfig="$scratch/controller.kubeconfig" set-context controller \
    --cluster=e2e --user=controller --namespace="$THORAX_E2E_NAMESPACE" >/dev/null
  kubectl config --kubeconfig="$scratch/controller.kubeconfig" use-context controller >/dev/null

  KUBECONFIG="$scratch/controller.kubeconfig" \
    target/debug/thorax-kubernetes-controller \
    --namespace "$THORAX_E2E_NAMESPACE" \
    --lease-name thorax-e2e-thorax-kubernetes-controller \
    --holder-identity acceptance-test >"$scratch/controller.log" 2>&1 &
  controller_pid=$!
  expected_holder=acceptance-test
fi

controller_service_account=thorax-e2e-thorax-kubernetes-controller
controller_principal="system:serviceaccount:${THORAX_E2E_NAMESPACE}:${controller_service_account}"
[[ "$(kubectl auth can-i list secrets --as="$controller_principal" -n "$THORAX_E2E_NAMESPACE")" == no ]]
[[ "$(kubectl auth can-i watch secrets --as="$controller_principal" -n "$THORAX_E2E_NAMESPACE")" == no ]]
[[ "$(kubectl auth can-i patch secrets --as="$controller_principal" -n "$THORAX_E2E_NAMESPACE")" == no ]]
[[ "$(kubectl auth can-i get secrets --as="$controller_principal" -n "$THORAX_E2E_NAMESPACE")" == yes ]]

kubectl -n "$THORAX_E2E_NAMESPACE" create secret generic admission-unrelated \
  --from-literal=value=unrelated >/dev/null
if kubectl --as="$controller_principal" -n "$THORAX_E2E_NAMESPACE" \
  create secret generic admission-forbidden-create --from-literal=value=forbidden \
  >"$scratch/forbidden-create.out" 2>&1; then
  echo "controller service account created a Secret without a Thorax owner" >&2
  exit 1
fi
cat >"$scratch/service-account-token-secret.yaml" <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: admission-token-escalation
  namespace: $THORAX_E2E_NAMESPACE
  labels:
    thorax.backbone.dev/managed: "true"
  annotations:
    kubernetes.io/service-account.name: default
  ownerReferences:
    - apiVersion: thorax.backbone.dev/v1alpha1
      kind: ThoraxSecret
      name: forged-owner
      uid: 00000000-0000-0000-0000-000000000001
      controller: true
type: kubernetes.io/service-account-token
YAML
if kubectl --as="$controller_principal" create \
  -f "$scratch/service-account-token-secret.yaml" >"$scratch/forbidden-token-create.out" 2>&1; then
  echo "controller service account requested a generated service-account token" >&2
  exit 1
fi
kubectl -n "$THORAX_E2E_NAMESPACE" get secret admission-unrelated -o json |
  jq '.metadata.labels = {"example.com/admission-test": "changed"} | del(.metadata.managedFields)' \
    >"$scratch/unrelated-update.json"
if kubectl --as="$controller_principal" -n "$THORAX_E2E_NAMESPACE" \
  replace -f "$scratch/unrelated-update.json" >"$scratch/forbidden-update.out" 2>&1; then
  echo "controller service account updated a Secret without a Thorax owner" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  holder=$(kubectl -n "$THORAX_E2E_NAMESPACE" get lease \
    thorax-e2e-thorax-kubernetes-controller -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)
  if [[ -n "$holder" && ( -z "$expected_holder" || "$holder" == "$expected_holder" ) ]]; then
    break
  fi
  sleep 1
done
[[ -n "${holder:-}" ]]
[[ -z "$expected_holder" || "$holder" == "$expected_holder" ]]

mkdir -p "$scratch/workspace" "$scratch/xdg"
cli_env=(env XDG_DATA_HOME="$scratch/xdg" THORAX_UNSAFE_KEYCHAIN_PASSPHRASE=acceptance-test-only)
"${cli_env[@]}" target/debug/thorax init --path "$scratch/workspace" --name acceptance --handle root >/dev/null
printf '%s' cnpg-password-v1 | "${cli_env[@]}" target/debug/thorax set --path "$scratch/workspace" db/prod/app >/dev/null
printf '%s' thorax_app | "${cli_env[@]}" target/debug/thorax field set --path "$scratch/workspace" db/prod/app username >/dev/null

kubectl -n "$THORAX_E2E_NAMESPACE" apply -f deploy/examples/kubernetes/thorax.yaml
"${cli_env[@]}" target/debug/thorax --path "$scratch/workspace" kubernetes publish payments \
  --namespace "$THORAX_E2E_NAMESPACE" --timeout 90 >/dev/null

request=""
for _ in $(seq 1 45); do
  request=$(kubectl -n "$THORAX_E2E_NAMESPACE" get thoraxvault payments \
    -o jsonpath='{.status.joinRequestName}' 2>/dev/null || true)
  [[ -n "$request" ]] && break
  sleep 1
done
[[ -n "$request" ]]
kubectl -n "$THORAX_E2E_NAMESPACE" patch configmap thorax-vault-payments --type=merge \
  -p='{"data":{"publish-sentinel":"preserved"}}' >/dev/null
"${cli_env[@]}" target/debug/thorax --path "$scratch/workspace" kubernetes approve payments \
  --namespace "$THORAX_E2E_NAMESPACE" --read-exact db/prod/app --yes >/dev/null
"${cli_env[@]}" target/debug/thorax --path "$scratch/workspace" kubernetes publish payments \
  --namespace "$THORAX_E2E_NAMESPACE" --timeout 90 >/dev/null
[[ "$(kubectl -n "$THORAX_E2E_NAMESPACE" get configmap thorax-vault-payments \
  -o jsonpath='{.data.publish-sentinel}')" == preserved ]]
[[ -n "$(kubectl -n "$THORAX_E2E_NAMESPACE" get configmap thorax-vault-payments \
  -o jsonpath='{.binaryData.vault\.cord}')" ]]

for _ in $(seq 1 45); do
  projected=$(kubectl -n "$THORAX_E2E_NAMESPACE" get secret pg-app \
    -o jsonpath='{.data.password}' 2>/dev/null | base64 -d || true)
  [[ "$projected" == cnpg-password-v1 ]] && break
  sleep 1
done
[[ "$projected" == cnpg-password-v1 ]]

# UPDATE containment must inspect the resulting object, not only oldObject. Attack the real,
# mutable controller-owned ratchet Secret so Kubernetes owner GC cannot race the assertion.
ratchet_secret=$(kubectl -n "$THORAX_E2E_NAMESPACE" get secret \
  -l thorax.backbone.dev/component=ratchet -o jsonpath='{.items[0].metadata.name}')
[[ -n "$ratchet_secret" ]]
kubectl -n "$THORAX_E2E_NAMESPACE" get secret "$ratchet_secret" -o json |
  jq '.type = "kubernetes.io/service-account-token" |
      .metadata.annotations = {"kubernetes.io/service-account.name":"default"} |
      del(.metadata.managedFields)' >"$scratch/forbidden-token-update.json"
if kubectl --as="$controller_principal" replace \
  -f "$scratch/forbidden-token-update.json" >"$scratch/forbidden-token-update.out" 2>&1; then
  echo "controller service account converted its ratchet into a service-account token" >&2
  exit 1
fi

kubectl -n "$THORAX_E2E_NAMESPACE" apply -f - <<'YAML'
apiVersion: thorax.backbone.dev/v1alpha1
kind: ThoraxSecret
metadata:
  name: shrink-test
spec:
  vaultRef:
    name: payments
  data:
    value:
      selector: db/prod/app
    removable:
      selector: db/prod/app
      field: username
  template:
    type: Opaque
YAML
for _ in $(seq 1 45); do
  removable=$(kubectl -n "$THORAX_E2E_NAMESPACE" get secret shrink-test \
    -o jsonpath='{.data.removable}' 2>/dev/null || true)
  [[ -n "$removable" ]] && break
  sleep 1
done
[[ -n "$removable" ]]
kubectl -n "$THORAX_E2E_NAMESPACE" patch thoraxsecret shrink-test --type=json \
  -p='[{"op":"remove","path":"/spec/data/removable"}]' >/dev/null
for _ in $(seq 1 45); do
  removable=$(kubectl -n "$THORAX_E2E_NAMESPACE" get secret shrink-test \
    -o jsonpath='{.data.removable}' 2>/dev/null || true)
  [[ -z "$removable" ]] && break
  sleep 1
done
[[ -z "$removable" ]]

kubectl -n "$THORAX_E2E_NAMESPACE" apply -f - <<'YAML'
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: pg
spec:
  instances: 1
  # CNPG parses the tag to determine PostgreSQL upgrade compatibility. The
  # digest remains the immutable pull identity; the tag supplies version
  # metadata to CNPG's admission webhook.
  imageName: ghcr.io/cloudnative-pg/postgresql:18.3-standard-trixie@sha256:d6f5ab6e8275f0eecf342e1bb8651fa0b428c23e9d743deb481aa3afd0cce397
  enableSuperuserAccess: true
  storage:
    size: 1Gi
  managed:
    roles:
      - name: thorax_app
        ensure: present
        login: true
        passwordSecret:
          name: pg-app
---
apiVersion: v1
kind: Pod
metadata:
  name: file-reader
spec:
  containers:
    - name: reader
      image: busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f
      command: [sh, -c, "sleep 3600"]
      volumeMounts:
        - name: credential
          mountPath: /secret
          readOnly: true
  volumes:
    - name: credential
      secret:
        secretName: pg-app
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: env-reader
spec:
  replicas: 1
  selector:
    matchLabels: { app: env-reader }
  template:
    metadata:
      labels: { app: env-reader }
    spec:
      containers:
        - name: reader
          image: busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f
          command: [sh, -c, "sleep 3600"]
          env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef: { name: pg-app, key: password }
YAML

kubectl -n "$THORAX_E2E_NAMESPACE" wait --for=condition=Ready cluster/pg --timeout=360s
kubectl -n "$THORAX_E2E_NAMESPACE" wait --for=condition=Ready pod/file-reader --timeout=240s
kubectl -n "$THORAX_E2E_NAMESPACE" rollout status deployment/env-reader --timeout=240s

primary=$(kubectl -n "$THORAX_E2E_NAMESPACE" get pod \
  -l cnpg.io/cluster=pg,role=primary -o jsonpath='{.items[0].metadata.name}')
initial_user=$(kubectl -n "$THORAX_E2E_NAMESPACE" exec "$primary" -- \
  env PGPASSWORD=cnpg-password-v1 psql -h pg-rw -U thorax_app -d postgres -tAc 'SELECT current_user')
[[ "$initial_user" == thorax_app ]]
[[ "$(kubectl -n "$THORAX_E2E_NAMESPACE" exec file-reader -- cat /secret/password)" == cnpg-password-v1 ]]

printf '%s' cnpg-password-v2 | "${cli_env[@]}" target/debug/thorax set \
  --path "$scratch/workspace" --rotate db/prod/app >/dev/null
"${cli_env[@]}" target/debug/thorax --path "$scratch/workspace" kubernetes publish payments \
  --namespace "$THORAX_E2E_NAMESPACE" --timeout 90 >/dev/null

accepted=no
for _ in $(seq 1 120); do
  if kubectl -n "$THORAX_E2E_NAMESPACE" exec "$primary" -- \
    env PGPASSWORD=cnpg-password-v2 psql -h pg-rw -U thorax_app -d postgres \
    -tAc 'SELECT current_user' 2>/dev/null | grep -Fxq thorax_app; then
    accepted=yes
    break
  fi
  sleep 2
done
[[ "$accepted" == yes ]]
if kubectl -n "$THORAX_E2E_NAMESPACE" exec "$primary" -- \
  env PGPASSWORD=cnpg-password-v1 psql -h pg-rw -U thorax_app -d postgres \
  -tAc 'SELECT current_user' >/dev/null 2>&1; then
  echo "superseded PostgreSQL password was still accepted" >&2
  exit 1
fi

file_value=""
for _ in $(seq 1 120); do
  file_value=$(kubectl -n "$THORAX_E2E_NAMESPACE" exec file-reader -- cat /secret/password 2>/dev/null || true)
  [[ "$file_value" == cnpg-password-v2 ]] && break
  sleep 2
done
[[ "$file_value" == cnpg-password-v2 ]]

env_pod=$(kubectl -n "$THORAX_E2E_NAMESPACE" get pod -l app=env-reader \
  -o jsonpath='{.items[0].metadata.name}')
[[ "$(kubectl -n "$THORAX_E2E_NAMESPACE" exec "$env_pod" -- printenv PGPASSWORD)" == cnpg-password-v1 ]]
kubectl -n "$THORAX_E2E_NAMESPACE" rollout restart deployment/env-reader >/dev/null
kubectl -n "$THORAX_E2E_NAMESPACE" rollout status deployment/env-reader --timeout=240s

new_env_pod=""
for _ in $(seq 1 30); do
  new_env_pod=$(kubectl -n "$THORAX_E2E_NAMESPACE" get pods -l app=env-reader -o json |
    jq -r '.items[] | select(.metadata.deletionTimestamp == null) | select(any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .metadata.name' |
    head -1)
  [[ -n "$new_env_pod" ]] && break
  sleep 1
done
[[ "$(kubectl -n "$THORAX_E2E_NAMESPACE" exec "$new_env_pod" -- printenv PGPASSWORD)" == cnpg-password-v2 ]]

projected_uid=$(kubectl -n "$THORAX_E2E_NAMESPACE" get secret pg-app -o jsonpath='{.metadata.uid}')
kubectl -n "$THORAX_E2E_NAMESPACE" patch configmap thorax-vault-payments --type=json \
  -p='[{"op":"replace","path":"/binaryData/vault.cord","value":"Y29ycnVwdA=="}]' >/dev/null
withdrawn=no
for _ in $(seq 1 60); do
  current_uid=$(kubectl -n "$THORAX_E2E_NAMESPACE" get secret pg-app \
    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
  if [[ "$current_uid" != "$projected_uid" ]]; then
    withdrawn=yes
    break
  fi
  sleep 1
done
[[ "$withdrawn" == yes ]]

# A consuming controller is outside Thorax's trust boundary and may create its
# own replacement after Thorax withdraws the object. CNPG does that for managed
# roles. Prove that Thorax removed its exact object and never adopts the
# consumer-owned replacement.
if [[ -n "$current_uid" ]]; then
  ! kubectl -n "$THORAX_E2E_NAMESPACE" get secret pg-app -o json |
    jq -e '.metadata.ownerReferences[]? |
      select(.apiVersion == "thorax.backbone.dev/v1alpha1" and .kind == "ThoraxSecret")' >/dev/null
fi

thorax_e2e_verify_environment

echo "Thorax/CNPG rotation acceptance passed"
