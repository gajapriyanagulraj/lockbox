# LockBox Demo Scenarios

These scenarios are configured for `ghcr.io/gajapriyanagulraj/lockbox`.

## Scenario A: Block Non-GHCR Registry

Run:

```bash
kubectl apply -f demo/denied-dockerhub.yaml
```

Expected result: Kyverno denies the admission request because the image is not from `ghcr.io`.

## Scenario B: Block latest Tag

Run:

```bash
kubectl apply -f demo/denied-latest.yaml
```

Expected result: Kyverno denies the admission request because `latest` is not allowed.

## Scenario C: Block Unsigned Image

Run:

```bash
kubectl apply -f demo/unsigned-ghcr.yaml
```

Expected result: Kyverno denies the admission request because no valid Cosign signature exists.

## Scenario D: Allow Signed Image

Run:

```bash
kubectl apply -f demo/signed-lockbox.yaml
```

Expected result: Kyverno admits the workload and the LockBox service becomes available.

## Useful Commands

```bash
kubectl apply -f policies/
kubectl apply -f kubernetes/
kubectl get pods
kubectl describe pod -l app=lockbox
kubectl port-forward svc/lockbox 8080:80
curl http://localhost:8080
```
