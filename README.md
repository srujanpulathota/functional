# Azure Function: Key Vault Replicator (Event Grid → Function)

This Function listens to Key Vault events and replicates new versions to a target Key Vault.

## Contents
- `host.json` — Functions host config
- `requirements.txt` — Python dependencies
- `ReplicateFromEventGrid/function.json` — Event Grid trigger binding
- `ReplicateFromEventGrid/__init__.py` — Function code

## App Setting (required)
- `TARGET_VAULT_NAME` — the name of the **target** Key Vault (no URL, just the name).

If you use a **User-Assigned Managed Identity**, also set:
- `AZURE_CLIENT_ID` — the client ID of that UAMI.

## Permissions (choose one model per vault)
**RBAC model (recommended):**
- Source KV: Key Vault Secrets User, Key Vault Crypto User, Key Vault Certificates User
- Target KV: Key Vault Secrets Officer, Key Vault Crypto Officer, Key Vault Certificates Officer

**OR Access Policy model (per-vault Access configuration = Vault access policy):**
- Source: Secrets (Get, List), Keys (Get, List), Certificates (Get, List)
- Target: Secrets (Set, Get, List), Keys (Create, Get, List, Update), Certificates (Import, Get, List, Update)

## Deploy (Zip Deploy)
1. Create a Function App (Python, Linux; Premium or Consumption).
2. Enable **System-assigned Managed Identity** on the Function App.
3. Set App Setting `TARGET_VAULT_NAME=<your-target-kv>`.
4. From your terminal:
   ```bash
   az functionapp deployment source config-zip      -g <resource-group>      -n <function-app-name>      --src azure-func-kv-replicator.zip
   ```

## Wire Event Grid to the Function
**Option A — Endpoint type: Azure Function**
- Key Vault → Events → + Event Subscription
- Event types: SecretNewVersionCreated, KeyNewVersionCreated, CertificateNewVersionCreated
- Endpoint type: Azure Function → choose `ReplicateFromEventGrid`

**Option B — Endpoint type: Webhook**
- In Portal → Function App → Functions → ReplicateFromEventGrid → **Get function URL**
- Use that URL as the webhook endpoint in the Event Subscription

## Local test (optional)
```bash
python3 -m venv venv
source venv/bin/activate   # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
func start
deactivate
```
