import os, re, logging
import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.certificates import CertificateClient

cred = ManagedIdentityCredential()

def kv_url(name: str) -> str:
    # name can be "kv-name" OR a full URL; normalize to name
    if name.startswith("https://"):
        host = name.split("://", 1)[1]
        name = host.split(".", 1)[0]
    return f"https://{name}.vault.azure.net"

_SUBJECT_RE = re.compile(
    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/([^/]+)/"
    r"(secrets|keys|certificates)/([^/]+)/([^/]+)$",
    re.IGNORECASE
)

def parse_event_fields(evt: func.EventGridEvent):
    """Return (event_type, vault_name, obj_kind, obj_name, version) from event."""
    etype = evt.event_type or ""
    data = {}
    try:
        data = evt.get_json() or {}
    except Exception:
        pass

    # Try data first
    vault = data.get("vaultName") or data.get("vaultUri") or data.get("vaultUrl")
    kind  = (data.get("objectType") or "").lower()
    name  = data.get("objectName")
    ver   = data.get("version")

    # Fallback to subject when missing (common)
    subj = evt.subject or ""
    m = _SUBJECT_RE.search(subj)
    if m:
        vault = vault or m.group(1)
        kind  = kind  or m.group(2)
        name  = name  or m.group(3)
        ver   = ver   or m.group(4)

    # Normalize vault name if it's a URL
    if vault and vault.startswith("https://"):
        host = vault.split("://", 1)[1]
        vault = host.split(".", 1)[0]

    return etype, vault, kind, name, ver

def main(event: func.EventGridEvent):
    etype, src_vault, obj_kind, obj_name, version = parse_event_fields(event)
    tgt_vault = os.environ.get("TARGET_VAULT_NAME")

    if not (obj_name and src_vault and tgt_vault and version):
        logging.error(f"Missing required fields after fallback. objectName={obj_name}, src={src_vault}, tgt={tgt_vault}, ver={version}")
        return

    logging.info(f"KV Replicator (EventGrid) triggered. type={etype} src={src_vault} objType={obj_kind} name={obj_name} ver={version}")

    try:
        if etype.endswith("SecretNewVersionCreated"):
            replicate_secret(src_vault, tgt_vault, obj_name, version)
        elif etype.endswith("KeyNewVersionCreated"):
            replicate_key_metadata(src_vault, tgt_vault, obj_name, version)
        elif etype.endswith("CertificateNewVersionCreated"):
            replicate_certificate_public(src_vault, tgt_vault, obj_name, version)
        else:
            logging.info(f"Ignored event type: {etype}")
    except Exception:
        logging.exception("Replication failed.")
