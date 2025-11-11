import os
import logging
import azure.functions as func

from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.certificates import CertificateClient

# If you use a User-Assigned Managed Identity, set AZURE_CLIENT_ID app setting to that UAMI's client ID.
cred = ManagedIdentityCredential()

def kv_url(name: str) -> str:
    return f"https://{name}.vault.azure.net"

def main(event: func.EventGridEvent):
    logging.info("KV Replicator (EventGrid) triggered.")
    try:
        data = event.get_json() or {}
    except Exception:
        logging.exception("Failed to parse Event Grid data.")
        return

    event_type = event.event_type or ""
    obj_name   = data.get("objectName")
    version    = data.get("version")
    src_vault  = data.get("vaultName")
    tgt_vault  = os.environ.get("TARGET_VAULT_NAME")

    if not (obj_name and src_vault and tgt_vault):
        logging.error(f"Missing required fields. objectName={obj_name}, src={src_vault}, tgt={tgt_vault}")
        return

    logging.info(f"EventType={event_type} Name={obj_name} Version={version} Src={src_vault} Tgt={tgt_vault}")

    try:
        if event_type.endswith("SecretNewVersionCreated"):
            replicate_secret(src_vault, tgt_vault, obj_name, version)
        elif event_type.endswith("KeyNewVersionCreated"):
            replicate_key_metadata(src_vault, tgt_vault, obj_name, version)
        elif event_type.endswith("CertificateNewVersionCreated"):
            replicate_certificate_public(src_vault, tgt_vault, obj_name, version)
        else:
            logging.info(f"Ignored event type: {event_type}")
    except Exception:
        logging.exception("Replication failed.")

def replicate_secret(src: str, tgt: str, name: str, version: str):
    src_client = SecretClient(kv_url(src), cred)
    tgt_client = SecretClient(kv_url(tgt), cred)

    # Read the new version from source
    secret = src_client.get_secret(name, version=version)
    # Write a new version on target with same value and contentType
    set_resp = tgt_client.set_secret(name, secret.value, content_type=secret.properties.content_type)

    # Copy tags (requires an update of properties)
    if secret.properties.tags:
        props = tgt_client.get_secret(name).properties
        props.tags = secret.properties.tags
        tgt_client.update_secret_properties(props)

    logging.info(f"[Secret] {name} → replicated. Target version={set_resp.properties.version}")

def replicate_key_metadata(src: str, tgt: str, name: str, version: str):
    src_client = KeyClient(kv_url(src), cred)
    tgt_client = KeyClient(kv_url(tgt), cred)

    # You cannot export non-exportable private key material from Key Vault.
    key = src_client.get_key(name, version=version)
    kty = key.key_type
    ops = key.key_operations

    # Create a comparable key on target (material is different by design)
    if kty in (KeyType.rsa, KeyType.rsa_hsm):
        size = getattr(key.key, "size", None) or 2048
        tgt_client.create_rsa_key(name=name, size=size, hardware_protected=False, key_operations=ops)
    elif kty in (KeyType.ec, KeyType.ec_hsm):
        curve = getattr(key.key, "crv", None) or "P-256"
        tgt_client.create_ec_key(name=name, curve=curve, hardware_protected=False, key_operations=ops)
    else:
        logging.warning(f"[Key] Type {kty} not auto-handled. Skipping {name}.")
        return

    # Copy tags (if any)
    if key.properties.tags:
        props = tgt_client.get_key(name).properties
        props.tags = key.properties.tags
        tgt_client.update_key_properties(props)

    logging.info(f"[Key] {name} → comparable key created on target (material not copied).")

def replicate_certificate_public(src: str, tgt: str, name: str, version: str):
    src_client = CertificateClient(kv_url(src), cred)
    tgt_client = CertificateClient(kv_url(tgt), cred)

    cert = src_client.get_certificate_version(name, version)
    # Import only the public certificate. Private key cannot be exported from KV if non-exportable.
    tgt_client.import_certificate(name=name, certificate_bytes=cert.cer)

    # Copy tags (if any)
    if cert.properties.tags:
        props = tgt_client.get_certificate(name).properties
        props.tags = cert.properties.tags
        tgt_client.update_certificate_properties(props)

    logging.info(f"[Cert] {name} → public certificate replicated.")
