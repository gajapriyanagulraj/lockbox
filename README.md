# LockBox

Zero-trust software supply chain security prototype using Docker, Trivy, Cosign, GHCR, Kyverno, and Kubernetes.

## What This Prototype Does

- Runs a small Flask service.
- Builds a container image.
- Generates a CycloneDX SBOM with Trivy.
- Scans the image for HIGH and CRITICAL vulnerabilities.
- Generates a visible Markdown and HTML security report.
- Pushes images to GitHub Container Registry.
- Signs images with Cosign keyless signing through GitHub OIDC.
- Enforces Kubernetes admission policies with Kyverno.

## Prerequisites

Install these tools locally:

- Docker
- Kind
- kubectl
- Helm
- Trivy
- Cosign

Verify:

```bash
docker version
kubectl version --client
kind version
helm version
trivy version
cosign version
```

## Local App Build

```bash
docker build -t lockbox:v1 app
docker run --rm -p 5000:5000 lockbox:v1
curl http://localhost:5000
```

## Generate SBOM and Scan

```bash
scripts/generate-sbom.sh lockbox:v1
scripts/scan-image.sh lockbox:v1
```

Raw scan data is written to `artifacts/`. Human-readable reports are written to:

- `reports/security-report.md`
- `public/index.html`

## Create Local Kubernetes Cluster

```bash
kind create cluster --name lockbox
kubectl get nodes
```

For a local-only deployment before GHCR signing is configured:

```bash
kind load docker-image lockbox:v1 --name lockbox
kubectl set image -f kubernetes/deployment.yaml lockbox=lockbox:v1 --local -o yaml | kubectl apply -f -
kubectl apply -f kubernetes/service.yaml
kubectl port-forward svc/lockbox 8080:80
curl http://localhost:8080
```

## GHCR Image Flow

```bash
docker tag lockbox:v1 ghcr.io/gajapriyanagulraj/lockbox:v1
docker login ghcr.io
docker push ghcr.io/gajapriyanagulraj/lockbox:v1
cosign sign --yes ghcr.io/gajapriyanagulraj/lockbox:v1
```

Verify:

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/gajapriyanagulraj/lockbox/.github/workflows/.+@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/gajapriyanagulraj/lockbox:v1
```

## Install Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl get pods -n kyverno
```

## Apply Policies

Apply:

```bash
kubectl apply -f policies/
kubectl apply -f kubernetes/
kubectl get pods
```

## GitHub Actions CI/CD

The workflow in `.github/workflows/pipeline.yaml` builds the image, creates `artifacts/sbom.json`, creates `artifacts/scan-report.json`, renders `reports/security-report.md`, publishes the report into the GitHub Actions job summary, pushes to GHCR on `main`, signs the pushed image using GitHub OIDC, and publishes `public/index.html` to GitHub Pages.

The final vulnerability gate fails the workflow when any HIGH or CRITICAL CVE is found.

Repository settings required:

- Enable GitHub Actions.
- Allow the workflow to write packages.
- Enable GitHub Pages with source set to GitHub Actions.
- Keep `permissions.id-token: write` in the workflow for keyless signing.

## Documentation

- [Architecture](docs/architecture.md)
- [Security Reporting](docs/reporting.md)
- [End-to-End Guide](docs/end-to-end-guide.md)
- [Demo Scenarios](docs/demo-scenarios.md)
