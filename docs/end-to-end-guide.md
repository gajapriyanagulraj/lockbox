# End-to-End Prototype Guide

This guide takes LockBox from local build to admission-control demo.

## 1. Install Tools

On macOS with Homebrew:

```bash
brew install kind kubectl helm trivy cosign
```

Docker Desktop must be installed and running.

Verify:

```bash
docker version
kind version
kubectl version --client
helm version
trivy version
cosign version
```

## 2. Build and Test the App

```bash
docker build -t lockbox:v1 app
docker run --rm -p 5000:5000 lockbox:v1
curl http://localhost:5000
```

Expected response:

```json
{"service":"lockbox","status":"healthy"}
```

## 3. Generate SBOM and Scan

```bash
scripts/generate-sbom.sh lockbox:v1
scripts/scan-image.sh lockbox:v1
```

Expected outputs:

```text
artifacts/sbom.json
artifacts/scan-report.json
```

## 4. Create Local Cluster

```bash
kind create cluster --name lockbox
kubectl get nodes
```

## 5. Push and Sign GHCR Image

Use the GitHub repository `gajapriyanagulraj/lockbox` and let GitHub Actions run on `main`.

The workflow builds:

```text
ghcr.io/gajapriyanagulraj/lockbox:<commit-sha>
ghcr.io/gajapriyanagulraj/lockbox:v1
```

It also signs both images using GitHub OIDC.

## 6. Confirm Manifests

The manifests are configured for `gajapriyanagulraj/lockbox` and `ghcr.io/gajapriyanagulraj/lockbox`.

## 7. Install Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl get pods -n kyverno
```

Wait until the Kyverno pods are running:

```bash
kubectl wait --for=condition=Ready pod -l app.kubernetes.io/part-of=kyverno -n kyverno --timeout=180s
```

## 8. Apply Policies

```bash
kubectl apply -f policies/
kubectl get clusterpolicy
```

## 9. Run Attack Simulations

Non-GHCR image should fail:

```bash
kubectl apply -f demo/denied-dockerhub.yaml
```

`latest` tag should fail:

```bash
kubectl apply -f demo/denied-latest.yaml
```

Unsigned GHCR image should fail:

```bash
kubectl apply -f demo/unsigned-ghcr.yaml
```

Signed LockBox image should pass:

```bash
kubectl apply -f demo/signed-lockbox.yaml
kubectl get pod signed-lockbox
```

## 10. Deploy the Service

```bash
kubectl apply -f kubernetes/
kubectl get pods
kubectl port-forward svc/lockbox 8080:80
curl http://localhost:8080
```

## 11. Cleanup

```bash
kubectl delete -f kubernetes/ --ignore-not-found
kubectl delete -f demo/ --ignore-not-found
kubectl delete -f policies/ --ignore-not-found
kind delete cluster --name lockbox
```
