import logging
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError

# ---------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------
TAG_FROM = "replicatedFrom"
TAG_BY = "replicatedBy"
TAG_BY_VALUE = "keyvaultsync"

MAX_ATTEMPTS = 3
attempt_cache = {}  # (src,tgt,name,version) → count


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
def kv_url(name: str) -> str:
    return f"https://{name}.vault.azure.net"


def kv_name(raw: str) -> str:
    """Normalize a vault name whether URL or raw."""
    if not raw:
        return ""
    raw = raw.lower()
    if ".vault.azure.net" in raw:
        return raw.split("//")[-1].split(".")[0]
    return raw


def should_skip_by_tags(tags: dict, src: str, tgt: str) -> bool:
    """Primary loop prevention using tags on the SOURCE version."""
    if not tags:
        return False

    tag_from = kv_name(tags.get(TAG_FROM, ""))
    tag_by = tags.get(TAG_BY, None)

    src_norm = kv_name(src)
    tgt_norm = kv_name(tgt)

    # If the version was created by this function and came from the opposite vault → skip
    if tag_by == TAG_BY_VALUE and tag_from == tgt_norm:
        logging.info(
            f"[LOOP-TAG] Skipping because source version already came FROM {tgt_norm}."
        )
        return True

    return False


def increment_attempt(src, tgt, name, version):
    key = f"{src}|{tgt}|{name}|{version}"
    attempt_cache[key] = attempt_cache.get(key, 0) + 1
    n = attempt_cache[key]

    logging.info(f"[LOOP-GUARD] Attempt {n}/{MAX_ATTEMPTS} for {key}")

    return n <= MAX_ATTEMPTS


# ---------------------------------------------------------
# REPLICATION LOGIC (SAFE)
# ---------------------------------------------------------
def replicate_secret(src: str, tgt: str, name: str, version: str, cred):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    # 1. Read the exact version
    try:
        sec = src_client.get_secret(name, version=version)
    except ResourceNotFoundError:
        logging.error(f"[ERROR] Source secret not found: {name}/{version}")
        return
    except HttpResponseError as ex:
        logging.error(f"[ERROR] Failed reading source secret: {ex}")
        return

    src_tags = dict(sec.properties.tags or {})

    # 2. TAG LOOP CHECK
    if should_skip_by_tags(src_tags, src, tgt):
        return

    # 3. SAFETY ATTEMPT CHECK
    if not increment_attempt(src, tgt, name, version):
        logging.error("[LOOP-GUARD] Max attempts exceeded. Skipping replication.")
        return

    # 4. Build new tags for target version
    new_tags = dict(src_tags)
    new_tags[TAG_FROM] = kv_name(src)
    new_tags[TAG_BY] = TAG_BY_VALUE

    # 5. Write to TARGET with tags in ONE operation (NO PATCH EVER!)
    try:
        written = tgt_client.set_secret(
            name,
            sec.value,
            content_type=sec.properties.content_type,
            tags=new_tags,
        )

        logging.info(
            f"[REPLICATED] {name}: {src} → {tgt}, "
            f"newVersion={written.properties.version}, tags={written.properties.tags}"
        )

    except HttpResponseError as ex:
        logging.error(f"[ERROR] Failed writing secret to {tgt}: {ex}")
        return


# ---------------------------------------------------------
# MAIN FUNCTION ENTRY
# ---------------------------------------------------------
def main(event: func.EventGridEvent):
    cred = DefaultAzureCredential()

    data = event.get_json()

    vault_raw = data.get("VaultName", "")
    vault = kv_name(vault_raw)
    name = data.get("ObjectName", None)
    version = data.get("Version", None)
    object_type = data.get("ObjectType", "").lower()

    logging.info(f"[EVENT] vault={vault} name={name} version={version} type={object_type}")

    # Only process secrets
    if object_type != "secret":
        logging.info("[SKIP] Not a secret event.")
        return

    # ---------------------------------------------
    # DEFINE THE TWO VAULTS THAT SHOULD SYNC
    # ---------------------------------------------
    vaultA = "qatioticpwu2-vault0"
    vaultB = "qatioticpscU-vault0"

    vA = kv_name(vaultA)
    vB = kv_name(vaultB)

    # Route event
    if vault == vA:
        src, tgt = vaultA, vaultB
    elif vault == vB:
        src, tgt = vaultB, vaultA
    else:
        logging.info("[SKIP] Vault is not in sync pair.")
        return

    if not name or not version:
        logging.error("[ERROR] Missing secret name or version in event.")
        return

    replicate_secret(src, tgt, name, version, cred)

    logging.info("[DONE] Event processed.")
