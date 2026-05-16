# Kubernetes manifests

Vanilla manifests for deploying SealKeeper on any conformant cluster.
For a templated, configurable variant, prefer the Helm chart in `../helm/`.

## Layout

| File | Purpose |
|------|---------|
| `namespace.yaml` | `sealkeeper` namespace with Pod Security Admission in `restricted` mode |
| `serviceaccount.yaml` | Dedicated SA, no auto-mounted token |
| `configmap.yaml` | Non-sensitive SK_* runtime config |
| `secret.example.yaml` | **Template** for SK_MASTER_SECRET, SK_DATABASE_URL, SK_METRICS_TOKEN (do NOT commit a real secret) |
| `deployment.yaml` | App `Deployment` (FR-H.30): 2 replicas, rolling update, readOnlyRoot, drop ALL, probes on `/healthz` + `/readyz` |
| `service.yaml` | `ClusterIP` on 8443 |
| `ingress.yaml` | `Ingress` for ingress-nginx, TLS via cert-manager (annotation commented) |
| `networkpolicy.yaml` | Default-deny + targeted allow (ingress controller → 8443, egress to DNS, PG, SMTP, SIEM) |
| `poddisruptionbudget.yaml` | `minAvailable: 1` for zero-downtime drains |
| `kustomization.yaml` | Bundles everything for `kubectl apply -k .` |

## Apply

```bash
# 1. Fill the secret out-of-band — never commit real values
cp secret.example.yaml secret.yaml
# edit secret.yaml: SK_MASTER_SECRET (openssl rand -base64 32), SK_DATABASE_URL
# then update kustomization.yaml to reference secret.yaml instead of the example

# 2. Apply everything
kubectl apply -k .

# 3. Watch rollout
kubectl -n sealkeeper rollout status deploy/sealkeeper
```

## Bring your own database

`secret.example.yaml` ships a placeholder `SK_DATABASE_URL` pointing at a
PostgreSQL service inside the same namespace. SealKeeper does **not**
provision a database — pick one of:

- **CloudNativePG** (recommended): `kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/main/releases/cnpg-1.24.1.yaml`
  then declare a `Cluster` in the `sealkeeper` namespace.
- **Zalando postgres-operator**.
- A managed offering (RDS, Cloud SQL, Azure Flexible Server). Update the
  `SK_DATABASE_URL` value accordingly and prefer `sslmode=verify-full`.

## Migrations

Schema migrations are forward-only (FR-H.61, D-D.13). The recommended path on
upgrade:

```bash
# Pull the new image
kubectl -n sealkeeper set image deploy/sealkeeper sealkeeper=ghcr.io/sealkeeper/sealkeeper:vX.Y.Z

# Run migrations from a one-shot Job (the binary's `migrate up` sub-command)
kubectl -n sealkeeper run sk-migrate --rm -it --restart=Never \
  --image=ghcr.io/sealkeeper/sealkeeper:vX.Y.Z \
  --env="SK_DATABASE_URL=$(kubectl -n sealkeeper get secret sealkeeper -o jsonpath='{.data.SK_DATABASE_URL}' | base64 -d)" \
  -- migrate up
```

Once migrations succeed, the rolling update completes itself.

## NetworkPolicy notes

`networkpolicy.yaml` is conservative: ingress is allowed only from the
`ingress-nginx` namespace. If your ingress controller lives elsewhere (Cilium,
Istio gateway, AWS Load Balancer Controller), edit the namespace label
selector to match. The egress SMTP/SIEM CIDRs are intentionally broad —
narrow them to the actual IPs of your relay and SIEM forwarder.
