import os
import re
import json
import logging
from typing import Optional, Tuple

import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.certificates import CertificateClient


# =========================================================
# Identity (supports system-assigned or user-assigned MI)
# =========================================================
# If you use a User-Assigned MI, set AZURE_CLIENT_ID in app settings.
cred = ManagedIdentityCredential()


# =========================================================
# Helper: KV name/URL normalization
# =========================================================
def kv_name_from_any(vault: Optional[str]) -> Optional[str]:
    """
    Accepts 'kv-name' or 'https://kv-name.vault.azure.net'
    and returns 'kv-name'.
    """
    if not vault:
        return vault
    if vault.startswith("https://"):
        host = vault.split("://", 1)[1]
        return host.split(".", 1)[0]
    return vault

def kv_url(vault_name: str) -> str:
    name = kv_name_from_any(vault_name)
    return f"https://{name}.vault.azure.net"


# =========================================================
# Regex for KV resource paths (for various schemas)
# =========================================================
RES_PATH = re.compile(
    r"(?:/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/vaults/([^/]+)"
    r"|https://([^.]+)\.vault\.azure\.net)"
    r"/(secrets|keys|certificates)/([^/]+)(?:/([^/]+))?$",
    re.IGNORECASE,
)

def _try_parse_any_path(s: Optional[str]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Return (vault, kind, name, version) from any KV-like path/URL string.
    """
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


# =========================================================
# Event parsing (case-insensitive data keys; robust)
# =========================================================
def parse_event_fields(evt: func.EventGridEvent):
    """
    Returns (event_type, vault_name, object_kind, object_name, version, raw_data_dict).
    Handles both classic and capitalized KV schemas.
    """
    etype = evt.event_type or ""
    topic = getattr(evt, "topic", None)
    subject = getattr(evt, "subject", None)

    raw = {}
    try:
        raw = evt.get_json() or {}
    except Exception:
        pass

    # Make a case-insensitive view of data keys
    data = {}
    try:
        data = { (k or ""): v for k, v in raw.items() }
        lower = { (k or "").lower(): v for k, v in raw.items() }
    except Exception:
        data = {}
        lower = {}

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

    # 3) Subject (may be full path or partial)
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

    # Normalize vault name if needed
    vault = kv_name_from_any(vault) if vault else vault

    return etype, vault, kind, name, ver, raw


# =========================================================
# Entrypoint – bi-directional sync with loop prevention
# =========================================================
def main(event: func.EventGridEvent):
    # Parse all event fields robustly
    etype, src_vault, obj_kind, obj_name, version, raw = parse_event_fields(event)

    # Read sync pair from app settings
    vault_a = kv_name_from_any(os.environ.get("SYNC_VAULT_A"))
    vault_b = kv_name_from_any(os.environ.get("SYNC_VAULT_B"))

    if not (vault_a and vault_b):
        logging.error("SYNC_VAULT_A and/or SYNC_VAULT_B not configured. Aborting.")
        return

    # Safe, high-signal logging of incoming event (no secret values)
    try:
        raw_str = json.dumps(raw)[:4000] if raw else "{}"
    except Exception:
        raw_str = "<unserializable>"

    logging.info(
        "KV Replicator triggered. "
        f"type={etype} src={src_vault} objType={obj_kind} objName={obj_name} "
        f"version={version} vaultA={vault_a} vaultB={vault_b} "
        f"subject={getattr(event,'subject',None)} topic={getattr(event,'topic',None)} "
        f"raw={raw_str}"
    )

    # If we don't know which vault this is, we can't route it
    if not src_vault:
        logging.error("Source vault could not be determined from event. Skipping.")
        return

    # Decide direction dynamically (bi-directional pair)
    src_v = kv_name_from_any(src_vault)
    if src_v == vault_a:
        tgt_v = vault_b
    elif src_v == vault_b:
        tgt_v = vault_a
    else:
        logging.info(f"Vault '{src_v}' is not in configured sync pair; ignoring event.")
        return

    if not obj_name:
        logging.error(f"No objectName resolved from event. src={src_v} tgt={tgt_v}")
        return

    # Dispatch based on type; if version missing, we handle latest in the replication functions
    try:
        if etype.endswith("SecretNewVersionCreated") or (obj_kind == "secrets"):
            replicate_secret_with_loop_guard(src_v, tgt_v, obj_name, version)
        elif etype.endswith("KeyNewVersionCreated") or (obj_kind == "keys"):
            replicate_key_with_loop_guard(src_v, tgt_v, obj_name, version)
        elif etype.endswith("CertificateNewVersionCreated") or (obj_kind == "certificates"):
            replicate_certificate_with_loop_guard(src_v, tgt_v, obj_name, version)
        else:
            logging.info(f"Ignored event type: {etype}")
    except Exception:
        logging.exception("Replication failed.")


# =========================================================
# Replication routines with loop prevention via tags
# =========================================================

LOOP_TAG_FROM = "replicatedFrom"
LOOP_TAG_BY   = "replicatedBy"
LOOP_TAG_BY_VAL = "keyvaultsync"


def _should_skip_replication(tags: Optional[dict], src: str, tgt: str) -> bool:
    """
    Decide if we should skip replication to avoid loops.
    We skip if:
      - The current version is clearly marked as created by this sync
        from the counterpart vault.
    """
    if not tags:
        return False

    src_norm = kv_name_from_any(src)
    tgt_norm = kv_name_from_any(tgt)
    tag_from = kv_name_from_any(tags.get(LOOP_TAG_FROM))
    tag_by   = tags.get(LOOP_TAG_BY)

    if tag_by == LOOP_TAG_BY_VAL and tag_from == tgt_norm:
        # This version is marked as having been created by our sync
        # from the target vault → don't send it back and create a loop.
        logging.info(
            f"Skipping replication for object marked as replicatedFrom={tag_from}, "
            f"replicatedBy={tag_by} (src={src_norm}, tgt={tgt_norm})."
        )
        return True

    return False


def replicate_secret_with_loop_guard(src: str, tgt: str, name: str, version: Optional[str]):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    # Read source (latest if version is missing)
    secret = src_client.get_secret(name, version=version) if version else src_client.get_secret(name)
    src_tags = dict(secret.properties.tags or {})

    # Loop-prevention check (on the source version)
    if _should_skip_replication(src_tags, src, tgt):
        return

    # Actually write to target
    set_resp = tgt_client.set_secret(name, secret.value, content_type=secret.properties.content_type)

    # Merge tags: copy user tags + loop metadata
    new_tags = dict(src_tags)  # start from source tags
    new_tags[LOOP_TAG_FROM] = kv_name_from_any(src)
    new_tags[LOOP_TAG_BY]   = LOOP_TAG_BY_VAL

    # Apply tags to the new target version
    props = set_resp.properties
    props.tags = new_tags
    tgt_client.update_secret_properties(props)

    logging.info(f"[Secret] {name} → replicated {src} -> {tgt}. Target version={set_resp.properties.version}")


def replicate_key_with_loop_guard(src: str, tgt: str, name: str, version: Optional[str]):
    src_client = KeyClient(kv_url(src), cred)
    tgt_client = KeyClient(kv_url(tgt), cred)

    key = src_client.get_key(name, version=version) if version else src_client.get_key(name)
    kty = key.key_type
    ops = key.key_operations
    src_tags = dict(key.properties.tags or {})

    # Loop-prevention check
    if _should_skip_replication(src_tags, src, tgt):
        return

    # Create comparable key on target (no private material export)
    created = None
    if kty in (KeyType.rsa, KeyType.rsa_hsm):
        size = getattr(key.key, "size", None) or 2048
        created = tgt_client.create_rsa_key(
            name=name,
            size=size,
            hardware_protected=False,
            key_operations=ops,
        )
    elif kty in (KeyType.ec, KeyType.ec_hsm):
        curve = getattr(key.key, "crv", None) or "P-256"
        created = tgt_client.create_ec_key(
            name=name,
            curve=curve,
            hardware_protected=False,
            key_operations=ops,
        )
    else:
        logging.warning(f"[Key] Type {kty} not auto-handled. Skipping {name}.")
        return

    # Apply tags (user + loop metadata)
    if created:
        new_tags = dict(src_tags)
        new_tags[LOOP_TAG_FROM] = kv_name_from_any(src)
        new_tags[LOOP_TAG_BY]   = LOOP_TAG_BY_VAL

        props = tgt_client.get_key(name).properties
        props.tags = new_tags
        tgt_client.update_key_properties(props)

    logging.info(f"[Key] {name} → replicated {src} -> {tgt} (comparable key, no material copy).")


def replicate_certificate_with_loop_guard(src: str, tgt: str, name: str, version: Optional[str]):
    src_client = CertificateClient(kv_url(src), cred)
    tgt_client = CertificateClient(kv_url(tgt), cred)

    cert = (
        src_client.get_certificate_version(name, version)
        if version
        else src_client.get_certificate(name)
    )
    src_tags = dict(cert.properties.tags or {})

    if _should_skip_replication(src_tags, src, tgt):
        return

    # Import only public certificate (private key not exported by Key Vault)
    imported = tgt_client.import_certificate(name=name, certificate_bytes=cert.cer)

    new_tags = dict(src_tags)
    new_tags[LOOP_TAG_FROM] = kv_name_from_any(src)
    new_tags[LOOP_TAG_BY]   = LOOP_TAG_BY_VAL

    props = imported.properties
    props.tags = new_tags
    tgt_client.update_certificate_properties(props)

    logging.info(f"[Cert] {name} → public cert replicated {src} -> {tgt}.")
