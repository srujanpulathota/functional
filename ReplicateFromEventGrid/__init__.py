import logging
import os
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
    if not raw:
        return ""
    raw = raw.lower()
    if ".vault.azure.net" in raw:
        return raw.split("//")[-1].split(".")[0]
    return raw


def should_skip_by_tags(tags: dict, src: str, tgt: str) -> bool:
    if not tags:
        return False

    tag_from = kv_name(tags.get(TAG_FROM, ""))
    tag_by = tags.get(TAG_BY)

    if tag_by == TAG_BY_VALUE and tag_from == kv_name(tgt):
        logging.info(
            f"[LOOP-TAG] Skipping: source version already came FROM {tgt}."
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
# SECRET REPLICATION
# ---------------------------------------------------------
def replicate_secret(src: str, tgt: str, name: str, version: str, cred):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    # Read source version
    try:
        sec = src_client.get_secret(name, version=version)
    except ResourceNotFoundError:
        logging.error(f"[ERROR] Source secret not found: {name}/{version}")
        return
    except HttpResponseError as ex:
        logging.error(f"[ERROR] Reading source secret: {ex}")
        return

    src_tags = dict(sec.properties.tags or {})

    # Loop prevention via tags
    if should_skip_by_tags(src_tags, src, tgt):
        return

    # Loop prevention via retry attempts
    if not increment_attempt(src, tgt, name, version):
        logging.error("[LOOP-GUARD] Max attempts exceeded. Skipping.")
        return

    # Build new tags
    new_tags = dict(src_tags)
    new_tags[TAG_FROM] = kv_name(src)
    new_tags[TAG_BY] = TAG_BY_VALUE

    # Create new version in target
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
        logging.error(f"[ERROR] Writing secret to {tgt}: {ex}")
        return


# ---------------------------------------------------------
# MAIN FUNCTION
# ---------------------------------------------------------
def main(event: func.EventGridEvent):
    cred = DefaultAzureCredential()

    data = event.get_json()

    vault_raw = data.get("VaultName", "")
    vault = kv_name(vault_raw)
    name = data.get("ObjectName")
    version = data.get("Version")
    obj_type = data.get("ObjectType", "").lower()

    logging.info(f"[EVENT] vault={vault} name={name} version={version} type={obj_type}")

    if obj_type != "secret":
        logging.info("[SKIP] Not a secret event.")
        return

    # -------------------------------------------------------------
    # READ VAULT PAIR FROM ENVIRONMENT VARIABLES (NON HARD-CODED)
    # -------------------------------------------------------------
    vaultA = kv_name(os.environ.get("VAULT_A", ""))
    vaultB = kv_name(os.environ.get("VAULT_B", ""))

    if not vaultA or not vaultB:
        logging.error("[ERROR] VAULT_A or VAULT_B is not configured in settings.")
        return

    if vault == vaultA:
        src = vaultA
        tgt = vaultB
    elif vault == vaultB:
        src = vaultB
        tgt = vaultA
    else:
        logging.info("[SKIP] Vault not in sync pair.")
        return

    if not name or not version:
        logging.error("[ERROR] Missing secret name/version in event.")
        return

    replicate_secret(src, tgt, name, version, cred)

    logging.info("[DONE] Event processed.")
