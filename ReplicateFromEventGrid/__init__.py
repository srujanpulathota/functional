import os
import re
import json
import logging
import azure.functions as func

from typing import Optional, Tuple
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.certificates import CertificateClient


# Identity (supports UAMI or system-assigned)
cred = ManagedIdentityCredential()


# ---------- Helpers: KV name/URL normalization ----------
def kv_name_from_any(vault: Optional[str]) -> Optional[str]:
    """Accepts 'kv-name' or 'https://kv-name.vault.azure.net' and returns 'kv-name'."""
    if not vault:
        return vault
    if vault.startswith("https://"):
        host = vault.split("://", 1)[1]
        return host.split(".", 1)[0]
    return vault

def kv_url(vault_name: str) -> str:
    name = kv_name_from_any(vault_name)
    return f"https://{name}.vault.azure.net"


# ---------- Regex for resource paths ----------
# Matches:
#   /subscriptions/.../vaults/<vault>/<kind>/<name>/<version>
#   https://<vault>.vault.azure.net/<kind>/<name>/<version?>
RES_PATH = re.compile(
    r"(?:/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/([^/]+)"
    r"|https://([^.]+)\.vault\.azure\.net)"
    r"/(secrets|keys|certificates)/([^/]+)(?:/([^/]+))?$",
    re.IGNORECASE,
)

def _try_parse_any_path(s: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Return (vault, kind, name, version) from any KV-like path/URL string."""
    if not s:
        return None, None, None, None
    m = RES_PATH.search(s)
    if not m:
        return None, None, None, None
    vault = m.group(1) or m.group(2)
    kind = m.group(3).lower() if m.group(3) else None
    name = m.group(4)
    ver  = m.group(5)
    return kv_name_from_any(vault), kind, name, ver


# ---------- Parse Event Grid event (case-insensitive) ----------
def parse_event_fields(evt: func.EventGridEvent):
    """
    Returns (event_type, vault_name, object_kind, object_name, version, raw_lower_dict).
    Accepts both classic and capitalized KV schemas. Pulls from data, id/url fields, subject, topic.
    """
    etype = evt.event_type or ""
    topic = getattr(evt, "topic", None)
    subject = getattr(evt, "subject", None)

    raw = {}
    try:
        raw = evt.get_json() or {}
    except Exception:
        pass

    # Lowercase the keys for case-insensitive lookups (but keep original in logs)
    data = {}
    try:
        data = { (k or ""): v for k, v in raw.items() }  # original
        lower = { (k or "").lower(): v for k, v in raw.items() }  # case-insensitive view
    except Exception:
        lower = {}
        data = {}

    # 1) Direct fields (case-insensitive)
    vault = lower.get("vaultname") or lower.get("vaulturi") or lower.get("vaulturl")
    kind  = (lower.get("objecttype") or "")
    kind  = kind.lower() if isinstance(kind, str) else None
    name  = lower.get("objectname")
    ver   = lower.get("version")

    # 2) Try ID/URL-like properties (both cases)
    url_candidates = [
        lower.get("id"), lower.get("objecturl"), lower.get("objecturi"),
        lower.get("uri"), lower.get("recoveryid"),
        data.get("Id"), data.get("ObjectUrl"), data.get("ObjectUri"),
        data.get("Uri"), data.get("RecoveryId"),
    ]
    for cand in url_candidates:
        v2, k2, n2, ver2 = _try_parse_any_path(cand)
        vault = vault or v2
        kind  = kind  or k2
        name  = name  or n2
        ver   = ver   or ver2
        if vault and name:
            break

    # 3) Subject
    v3, k3, n3, ver3 = _try_parse_any_path(subject)
    vault = vault or v3
    kind  = kind  or k3
    name  = name  or n3
    ver   = ver   or ver3

    # 4) Topic (often only the vault path)
    if topic and not vault:
        m = re.search(r"/providers/Microsoft\.KeyVault/vaults/([^/]+)$", topic, re.IGNORECASE)
        if m:
            vault = m.group(1)

    # Normalize vault name if URL
    vault = kv_name_from_any(vault) if vault else vault

    return etype, vault, kind, name, ver, raw


# ---------- Entrypoint ----------
def main(event: func.EventGridEvent):
    etype, src_vault, obj_kind, obj_name, version, raw = parse_event_fields(event)

    tgt_vault = os.environ.get("TARGET_VAULT_NAME")
    tgt_vault_name = kv_name_from_any(tgt_vault) if tgt_vault else None

    # Safe, high-signal logging (truncate raw)
    try:
        raw_str = json.dumps(raw)[:4000] if raw else "{}"
    except Exception:
        raw_str = "<unserializable>"

    logging.info(
        "KV Replicator triggered. "
        f"type={etype} src={src_vault} objType={obj_kind} objName={obj_name} "
        f"version={version} tgt={tgt_vault} subject={getattr(event,'subject',None)} "
        f"topic={getattr(event,'topic',None)} raw={raw_str}"
    )

    # Hard fail if we still don't have the basics (no name = nothing to copy)
    if not (obj_name and src_vault and tgt_vault_name):
        logging.error(
            "Missing required fields after fallback. "
            f"objectName={obj_name}, src={src_vault}, tgt={tgt_vault}, ver={version}"
        )
        return

    try:
        # If version is missing, we'll read latest
        if etype.endswith("SecretNewVersionCreated") or (obj_kind == "secrets"):
            replicate_secret(src_vault, tgt_vault_name, obj_name, version)
        elif etype.endswith("KeyNewVersionCreated") or (obj_kind == "keys"):
            replicate_key_metadata(src_vault, tgt_vault_name, obj_name, version)
        elif etype.endswith("CertificateNewVersionCreated") or (obj_kind == "certificates"):
            replicate_certificate_public(src_vault, tgt_vault_name, obj_name, version)
        else:
            logging.info(f"Ignored event type: {etype}")
    except Exception:
        logging.exception("Replication failed.")


# ---------- Replication routines ----------
def replicate_secret(src: str, tgt: str, name: str, version: Optional[str]):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    # Read latest if version absent
    secret = src_client.get_secret(name, version=version) if version else src_client.get_secret(name)
    set_resp = tgt_client.set_secret(name, secret.value, content_type=secret.properties.content_type)

    # Copy tags
    if secret.properties.tags:
        props = tgt_client.get_secret(name).properties
        props.tags = secret.properties.tags
        tgt_client.update_secret_properties(props)

    logging.info(f"[Secret] {name} → replicated to '{tgt}'. Target version={set_resp.properties.version}")


def replicate_key_metadata(src: str, tgt: str, name: str, version: Optional[str]):
    src_client = KeyClient(kv_url(src), cred)
    tgt_client = KeyClient(kv_url(tgt), cred)

    key = src_client.get_key(name, version=version) if version else src_client.get_key(name)
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

    logging.info(f"[Key] {name} → created comparable key on target '{tgt}' (material not copied).")


def replicate_certificate_public(src: str, tgt: str, name: str, version: Optional[str]):
    src_client = CertificateClient(kv_url(src), cred)
    tgt_client = CertificateClient(kv_url(tgt), cred)

    cert = (
        src_client.get_certificate_version(name, version)
        if version
        else src_client.get_certificate(name)  # latest
    )

    tgt_client.import_certificate(name=name, certificate_bytes=cert.cer)

    if cert.properties.tags:
        props = tgt_client.get_certificate(name).properties
        props.tags = cert.properties.tags
        tgt_client.update_certificate_properties(props)

    logging.info(f"[Cert] {name} → public certificate replicated to '{tgt}'.")
