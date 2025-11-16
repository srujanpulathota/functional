import logging
import json
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

# ---------------------------------------------
# CONSTANTS
# ---------------------------------------------
LOOP_TAG_FROM = "replicatedFrom"
LOOP_TAG_BY = "replicatedBy"
LOOP_TAG_BY_VAL = "keyvaultsync"

MAX_ATTEMPTS = 3  # safety guard


# ---------------------------------------------
# HELPERS
# ---------------------------------------------
def kv_url(name: str) -> str:
    return f"https://{name}.vault.azure.net"


def kv_name(url_or_name: str) -> str:
    """Normalize vault name from URL or raw name."""
    if ".vault.azure.net" in url_or_name:
        return url_or_name.split("//")[-1].split(".")[0].lower()
    return url_or_name.lower()


def should_skip_by_tags(tags: dict, src: str, tgt: str) -> bool:
    """Loop prevention via tags."""
    if not tags:
        return False

    src_norm = kv_name(src)
    tgt_norm = kv_name(tgt)
    tag_from = kv_name(tags.get(LOOP_TAG_FROM, ""))
    tag_by = tags.get(LOOP_TAG_BY)

    if tag_by == LOOP_TAG_BY_VAL and tag_from == tgt_norm:
        logging.info(
            f"[TAG-CHECK] Loop detected. "
            f"replicatedFrom={tag_from} replicatedBy={tag_by}. Skipping."
        )
        return True

    return False


attempt_cache = {}  # (src, tgt, name, version) → attempts


def increment_loop_attempt(src, tgt, name, version) -> bool:
    """Loop-prevention via attempt count."""
    key = f"{src}|{tgt}|{name}|{version}"
    attempt_cache[key] = attempt_cache.get(key, 0) + 1
    attempt = attempt_cache[key]
    logging.info(f"[LOOP-GUARD] Attempt {attempt}/{MAX_ATTEMPTS} for {key}")

    if attempt > MAX_ATTEMPTS:
        logging.error(f"[LOOP-GUARD] Max attempts exceeded for {key}. Skipping.")
        return False
    return True


# ---------------------------------------------
# SECRET REPLICATION WITH TAGS
# ---------------------------------------------
def replicate_secret(src: str, tgt: str, name: str, version: str, cred):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    # 1. Read source secret
    try:
        sec = src_client.get_secret(name, version=version)
    except ResourceNotFoundError:
        logging.error(f"[ERROR] Source secret not found: {name} ({version})")
        return
    except HttpResponseError as ex:
        logging.error(f"[ERROR] Failed to read source secret: {ex}")
        return

    src_tags = dict(sec.properties.tags or {})

    # 2. Tag-based loop check
    if should_skip_by_tags(src_tags, src, tgt):
        return

    # 3. Prevent infinite retries
    if not increment_loop_attempt(src, tgt, name, version):
        return

    # 4. Build new tags on TARGET
    new_tags = dict(src_tags)
    new_tags[LOOP_TAG_FROM] = kv_name(src)
    new_tags[LOOP_TAG_BY] = LOOP_TAG_BY_VAL

    # 5. Create new version on target WITH tags in one call
    try:
        created = tgt_client.set_secret(
            name,
            sec.value,
            content_type=sec.properties.content_type,
            tags=new_tags,
        )

        logging.info(
            f"[SECRET-REPLICATED] {name} {src} → {tgt} "
            f"version={created.properties.version} "
            f"tags={created.properties.tags}"
        )

    except HttpResponseError as ex:
        logging.error(f"[ERROR] WRITE FAILED for {name} to {tgt}: {ex}")
        return


# ---------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------
def main(event: func.EventGridEvent):
    cred = DefaultAzureCredential()

    # raw event data from Key Vault
    data = event.get_json()

    vault = kv_name(data.get("VaultName", ""))
    obj_type = data.get("ObjectType")
    name = data.get("ObjectName")
    version = data.get("Version")

    logging.info(f"[EVENT] type={event.event_type} vault={vault} name={name} version={version}")

    if obj_type.lower() != "secret":
        logging.info("[SKIP] Not a secret event.")
        return

    # -----------------------------------
    # DEFINE YOUR SOURCE/TARGET VAULTS
    # -----------------------------------
    vaultA = "qatioticpwu2-vault0"
    vaultB = "qatioticpScu-vault0"

    # Determine sync direction
    if vault == kv_name(vaultA):
        src = vaultA
        tgt = vaultB
    elif vault == kv_name(vaultB):
        src = vaultB
        tgt = vaultA
    else:
        logging.info("[SKIP] Vault not part of sync pair.")
        return

    # Execute replication
    replicate_secret(src, tgt, name, version, cred)

    logging.info(f"[DONE] Processed {name} version={version}")
