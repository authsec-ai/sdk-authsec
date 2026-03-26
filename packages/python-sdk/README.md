# AuthSec SDK — Python

Zero-config workload identity for your services. Get mTLS certificates, validate JWT-SVIDs, and enable service-to-service authentication — all through the ICP Agent running on your infrastructure.

## Install

```bash
pip install git+https://github.com/authsec-ai/sdk-authsec.git#subdirectory=packages/python-sdk
```

## Quick Start

### 1. Get workload identity (X.509-SVID)

```python
from authsec_sdk import QuickStartSVID

# One line — connects to agent, fetches SVID, enables auto-renewal
svid = await QuickStartSVID.initialize(
    socket_path="/run/spire/sockets/agent.sock"
)

print(f"Identity: {svid.spiffe_id}")
# spiffe://9936a009-.../workload/my-service
```

### 2. Run an mTLS server (FastAPI + Uvicorn)

```python
import uvicorn
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "ok", "identity": svid.spiffe_id}

# Start with mTLS — only callers with valid SVIDs can connect
uvicorn.run(
    app,
    host="0.0.0.0",
    port=8443,
    ssl_keyfile=str(svid.key_file_path),
    ssl_certfile=str(svid.cert_file_path),
    ssl_ca_certs=str(svid.ca_file_path),
    ssl_cert_reqs=2,  # CERT_REQUIRED
)
```

### 3. Call another service over mTLS

```python
import httpx

ssl_ctx = svid.create_ssl_context_for_client()

async with httpx.AsyncClient(verify=ssl_ctx) as client:
    resp = await client.get("https://other-service:8443/health")
    print(resp.json())
```

### 4. Validate incoming JWT-SVIDs

When another service sends a JWT-SVID in the `Authorization: Bearer` header, validate it:

```python
token = request.headers["Authorization"].split(" ")[1]

result = await svid.validate_jwt_svid(token, audience="my-api")
if result:
    print(f"Caller: {result['spiffe_id']}")
    print(f"Claims: {result['claims']}")
else:
    print("Invalid token")
```

### 5. Fetch a JWT-SVID (to call a permission-protected service)

```python
token = await svid.fetch_jwt_svid(audience=["target-api"])

# Send as Bearer token alongside mTLS
headers = {"Authorization": f"Bearer {token}"}
resp = await client.post("https://other-service:8443/action", headers=headers, json={...})
```

## Full Example — Service with mTLS + JWT-SVID

```python
import asyncio, os, ssl
from fastapi import FastAPI, Request, HTTPException
import uvicorn
from authsec_sdk import QuickStartSVID

app = FastAPI()
svid = None

@app.on_event("startup")
async def startup():
    global svid
    svid = await QuickStartSVID.initialize(
        socket_path=os.getenv("SPIFFE_ENDPOINT_SOCKET", "/run/spire/sockets/agent.sock")
    )

@app.get("/health")
async def health():
    return {"status": "ok", "spiffe_id": svid.spiffe_id}

@app.post("/protected-action")
async def protected(request: Request):
    # Verify caller's JWT-SVID
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "JWT-SVID required")

    result = await svid.validate_jwt_svid(auth.split(" ")[1], audience="my-api")
    if not result:
        raise HTTPException(403, "Invalid JWT-SVID")

    caller = result["spiffe_id"]
    claims = result["claims"]

    # Check permissions from claims
    if "my-resource:write" not in claims.get("permissions", []):
        raise HTTPException(403, "Insufficient permissions")

    return {"message": "success", "caller": caller}

if __name__ == "__main__":
    asyncio.run(startup())
    uvicorn.run(
        app, host="0.0.0.0", port=8443,
        ssl_keyfile=str(svid.key_file_path),
        ssl_certfile=str(svid.cert_file_path),
        ssl_ca_certs=str(svid.ca_file_path),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
```

## Kubernetes Deployment

Your workload needs two things:

1. **Mount the agent socket** as a volume
2. **Set `SPIFFE_ENDPOINT_SOCKET`** environment variable

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-service
spec:
  template:
    spec:
      serviceAccountName: my-service  # Must match registered workload entry
      containers:
        - name: my-service
          image: my-registry/my-service:latest
          env:
            - name: SPIFFE_ENDPOINT_SOCKET
              value: "/run/spire/sockets/agent.sock"
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: POD_UID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.uid
            - name: SERVICE_ACCOUNT
              valueFrom:
                fieldRef:
                  fieldPath: spec.serviceAccountName
            - name: POD_LABEL_APP
              valueFrom:
                fieldRef:
                  fieldPath: metadata.labels['app']
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: Directory
```

## Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install AuthSec SDK
RUN pip install git+https://github.com/authsec-ai/sdk-authsec.git#subdirectory=packages/python-sdk

COPY . .
CMD ["python", "main.py"]
```

## API Reference

### `QuickStartSVID`

| Method | Description |
|---|---|
| `await QuickStartSVID.initialize(socket_path)` | Connect to agent, fetch SVID, start auto-renewal. Returns singleton. |
| `await svid.validate_jwt_svid(token, audience)` | Validate a JWT-SVID via agent. Returns `{'spiffe_id': ..., 'claims': {...}}` or `None`. |
| `await svid.fetch_jwt_svid(audience, spiffe_id?)` | Fetch a JWT-SVID from the agent. Returns token string or `None`. |
| `svid.create_ssl_context_for_server()` | SSL context for mTLS server (requires client certs). |
| `svid.create_ssl_context_for_client()` | SSL context for mTLS client (presents SVID cert). |
| `svid.spiffe_id` | Current SPIFFE ID string. |
| `svid.certificate` | PEM certificate string. |
| `svid.private_key` | PEM private key string. |
| `svid.trust_bundle` | PEM CA bundle string. |
| `svid.cert_file_path` | Path to cert file on disk (auto-updated on renewal). |
| `svid.key_file_path` | Path to key file on disk. |
| `svid.ca_file_path` | Path to CA bundle file on disk. |

## How It Works

```
Your Service  →  SDK (QuickStartSVID)  →  gRPC Unix Socket  →  ICP Agent  →  ICP Service
                                                                   ↑
                                                          (runs on same node,
                                                           handles all crypto)
```

- The SDK talks to the **ICP Agent** via a local Unix socket — no network calls from your code
- The agent handles node attestation, workload attestation, cert issuance, and rotation
- Your service never needs to know the ICP Service URL, CA bundles, or tenant configuration
- Certificates auto-renew in the background — no restarts needed

## Requirements

- Python >= 3.10
- ICP Agent running on the same node (deployed by your platform team)
- Workload entry registered for your service's namespace + service account
