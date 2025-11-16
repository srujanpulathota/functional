import os
import json
import logging
from typing import Optional, Dict, Tuple
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.certificates import CertificateClient
import azure.functions as func

# ============================================================
# GLOBAL LOOP GUARD (process-wide)
# ============================================================
# Structure: { "<secret>|<version>|<src>|<tgt>": attempt_count }
LOOP_ATTEMPT_CACHE: Dict[str, int] = {}

# ============================================================
# CONSTANT TAGS
# ============================================================
LOOP_TAG_FROM = "replicatedFrom"
LOOP_TAG_BY = "replicatedBy"
LOOP_TAG_BY_VAL = "keyvaultsync"

# ============================================================
# AUTH
# ============================================================
cred = ManagedIdentityCredential()


# ============================================================
# UTILITIES
# ============================================================
def kv_name(vault: str) -> str:
    if vault.startswith("https://"):
        return vault.split("://")[1].split(".")[0]
    return vault


def kv_url(name: str) -> str:
    return f"https://{kv_name(name)}.vault.azure.net"


def parse_event_fields(evt: func.EventGridEvent) -> Tuple[str, str, str, str, str]:
    """
    Extract event_type, vault_name, obj_type, obj_name, version.
    """
    body = evt.get_json()
    event_type = evt.event_type
    subject = evt.subject
    topic = evt.topic

    vault = None
    name = None
    version = None
    kind = None

    # Common fields
    if "VaultName" in body:
        vault = body["VaultName"]
    if "ObjectName" in body:
        name = body["ObjectName"]
    if "Version" in body:
        version = body["Version"]
    if "ObjectType" in body:
        kind = body["ObjectType"].lower()

    # Try parsing from subject (like "secrets/foo/bar")
    if subject:
        parts = subject.split("/")
        if len(parts) >= 2:
            kind = kind or parts[0].lower()
            name = name or parts[1]
        if len(parts) >= 3:
            version = version or parts[2]

    # Topic contains the KV path
    if topic and "vaults" in topic.lower():
        v = topic.split("/vaults/")[-1]
        vault = vault or v

    return (
        event_type,
        kv_name(vault),
        kind,
        name,
        version,
    )


# ============================================================
# LOOP PROTECTION LOGIC
# ============================================================
def get_loop_key(src: str, tgt: str, name: str, version: Optional[str]) -> str:
    v = version or "NOVERSION"
    return f"{src}|{tgt}|{name}|{v}"


def increment_loop_attempt(src: str, tgt: str, name: str, version: Optional[str]) -> bool:
    """
    Returns True if we should proceed.
    Returns False if max attempts exceeded.
    """
    key = get_loop_key(src, tgt, name, version)
    LOOP_ATTEMPT_CACHE[key] = LOOP_ATTEMPT_CACHE.get(key, 0) + 1

    attempts = LOOP_ATTEMPT_CACHE[key]
    logging.info(f"[LOOP-GUARD] Attempt {attempts}/3 for {key}")

    if attempts > 3:
        logging.error(f"[LOOP-GUARD] Max attempts exceeded for {key}. Skipping replication.")
        return False
    return True


def should_skip_by_tags(tags: dict, src: str, tgt: str) -> bool:
    """
    SKIP IF:
    replicatedBy = keyvaultsync AND replicatedFrom = <tgt>
    """
    if not tags:
        return False

    replicated_from = kv_name(tags.get(LOOP_TAG_FROM, ""))
    replicated_by = tags.get(LOOP_TAG_BY)

    logging.info(
        f"[TAG-CHECK] Source tags => replicatedFrom={replicated_from}, replicatedBy={replicated_by}"
    )

    if replicated_by == LOOP_TAG_BY_VAL and replicated_from == kv_name(tgt):
        logging.info("[TAG-CHECK] Detected loop. Skipping replication.")
        return True

    return False


# ============================================================
# SECRET REPLICATION WITH TAG FIX
# ============================================================
def replicate_secret(src: str, tgt: str, name: str, version: Optional[str]):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    # Read source secret
    sec = src_client.get_secret(name, version=version)
    src_tags = dict(sec.properties.tags or {})

    # Loop prevention based on tags
    if should_skip_by_tags(src_tags, src, tgt):
        return

    # Loop prevention based on attempt count
    if not increment_loop_attempt(src, tgt, name, version):
        return

    # Write new secret version to target
    created = tgt_client.set_secret(
        name,
        sec.value,
        content_type=sec.properties.content_type,
        tags=src_tags  # initial tags BEFORE adding loop markers
    )

    # ADD loop tags
    updated_tags = dict(created.properties.tags or {})
    updated_tags[LOOP_TAG_FROM] = kv_name(src)
    updated_tags[LOOP_TAG_BY] = LOOP_TAG_BY_VAL

    # IMPORTANT: Update tags using correct SDK pattern
    tgt_client.update_secret_properties(
        created.properties,
        tags=updated_tags
    )

    logging.info(
        f"[SECRET-REPLICATED] {name} {src} -> {tgt} version={created.properties.version} "
        f"tags={updated_tags}"
    )


# ============================================================
# MAIN ENTRYPOINT
# ============================================================
def main(event: func.EventGridEvent):
    event_type, vault, kind, name, version = parse_event_fields(event)

    logging.info(
        f"[EVENT] type={event_type} vault={vault} name={name} version={version}"
    )

    if not vault or not name:
        logging.error("[ERROR] Missing vault or name. Skipping.")
        return

    vault_a = kv_name(os.environ.get("SYNC_VAULT_A", ""))
    vault_b = kv_name(os.environ.get("SYNC_VAULT_B", ""))

    if vault not in (vault_a, vault_b):
        logging.info("[INFO] Vault not part of sync pair. Ignoring.")
        return

    src = vault
    tgt = vault_b if vault == vault_a else vault_a

    if kind == "secret":
        replicate_secret(src, tgt, name, version)
    else:
        logging.info(f"[INFO] Skipping unhandled type: {kind}")
