import os
import re
import logging
import azure.functions as func

from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.certificates import CertificateClient

# If using a User-Assigned MI, set AZURE_CLIENT_ID app setting to that UAMI's client ID.
cred = ManagedIdentityCredential()

def kv_name_from_any(vault: str) -> str:
    """Accepts 'kv-name' or 'https://kv-name.vault.azure.net', returns 'kv-name'."""
    if not vault:
        return vault
    if vault.startswith("https://"):
        host = vault.split("://", 1)[1]
        return host.split(".", 1)[0]
    return vault

def kv_url(vault_name: str) -> str:
    return f"https://{kv_name_from_any(vault_name)}.vault.azure.net"

# Subject looks like:
# /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>/(secrets|keys|certificates)/<name>/<version>
_SUBJECT_RE = re.compile(
    r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/([^/]+)/"
    r"(secrets|keys|certificates)/([^/]+)/([^/]+)$",
    re.IGNORECASE
)

def parse_event_fields(evt: func.EventGridEvent):
    """Return (event_type, vault_name, object_kind, object_name, version)."""
    etype = evt.event_type or ""
    data = {}
    try:
        data = evt.get_json() or {}
    except Exception:
        pass

    # Try the data payload first
    vault = data.get("vaultName") or data.get("vaultUri") or data.get("vaultUrl")
    kind  = (data.get("objectType") or "").lower()
    name  = data.get("objectName")
    ver   = data.get("version")

    # Fallback to subject parsing (always present)
    subj = evt.subject or ""
    m = _SUBJECT_RE.search(subj)
    if m:
        vault = vault or m.group(1)
        kind  = kind  or m.group(2)
        name  = name  or m.group(3)
        ver   = ver   or m.group(4)

    # Normalize vault name if it was a URL
    vault = kv_name_from_any(vault) if vault else vault
    return etype, vault, kind, name, ver

def main(event: func.EventGridEvent):
    etype, src_vault, obj_kind, obj_name, version = parse_event_fields(event)
    tgt_vault = os.environ.get("TARGET_VAULT_NAME")

    if not (obj_name and src_vault and tgt_vault and version):
        logging.error(
            f"Missing required fields after fallback. objectName={obj_name}, "
            f"src={src_vault}, tgt={tgt_vault}, ver={version}"
        )
        return

    logging.info(
        f"KV Replicator (EventGrid) triggered. type={etype} src={src_vault} "
        f"objType={obj_kind} name={obj_name} ver={version}"
    )

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

def replicate_secret(src: str, tgt: str, name: str, version: str):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    secret = src_client.get_secret(name, version=version)
    set_resp = tgt_client.set_secret(name, secret.value, content_type=secret.properties.content_type)

    if secret.properties.tags:
        props = tgt_client.get_secret(name).properties
        props.tags = secret.properties.tags
        tgt_client.update_secret_properties(props)

    logging.info(f"[Secret] {name} → replicated. Target version={set_resp.properties.version}")

def replicate_key_metadata(src: str, tgt: str, name: str, version: str):
    src_client = KeyClient(kv_url(src), cred)
    tgt_client = KeyClient(kv_url(tgt), cred)

    key = src_client.get_key(name, version=version)
    kty = key.key_type
    ops = key.key_operations

    if kty in (KeyType.rsa, KeyType.rsa_hsm):
        size = getattr(key.key, "size", None) or 2048
        tgt_client.create_rsa_key(name=name, size=size, hardware_protected=False, key_operations=ops)
    elif kty in (KeyType.ec, KeyType.ec_hsm):
        curve = getattr(key.key, "crv", None) or "P-256"
        tgt_client.create_ec_key(name=name, curve=curve, hardware_protected=False, key_operations=ops)
    else:
        logging.warning(f"[Key] Type {kty} not auto-handled. Skipping {name}.")
        return

    if key.properties.tags:
        props = tgt_client.get_key(name).properties
        props.tags = key.properties.tags
        tgt_client.update_key_properties(props)

    logging.info(f"[Key] {name} → comparable key created on target (material not copied).")

def replicate_certificate_public(src: str, tgt: str, name: str, version: str):
    src_client = CertificateClient(kv_url(src), cred)
    tgt_client = CertificateClient(kv_url(tgt), cred)

    cert = src_client.get_certificate_version(name, version)
    tgt_client.import_certificate(name=name, certificate_bytes=cert.cer)

    if cert.properties.tags:
        props = tgt_client.get_certificate(name).properties
        props.tags = cert.properties.tags
        tgt_client.update_certificate_properties(props)

    logging.info(f"[Cert] {name} → public certificate replicated.")
