import os
import re
import json
import logging
import azure.functions as func

from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.certificates import CertificateClient

cred = ManagedIdentityCredential()

ALLOWED_EVENTS = (
    "Microsoft.KeyVault.SecretNewVersionCreated",
    "Microsoft.KeyVault.KeyNewVersionCreated",
    "Microsoft.KeyVault.CertificateNewVersionCreated",
)

def kv_url(name: str) -> str:
    return f"https://{name}.vault.azure.net"

def parse_from_topic(topic: str):
    if not topic:
        return None
    m = re.search(r"/providers/microsoft\.keyvault/vaults/([^/]+)", topic, re.IGNORECASE)
    return m.group(1) if m else None

def parse_from_subject(subject: str):
    if not subject:
        return None, None, None
    parts = [p for p in subject.split("/") if p]
    if len(parts) >= 2:
        obj_type_raw, obj_name = parts[0].lower(), parts[1]
        version = parts[2] if len(parts) >= 3 else None
        if obj_type_raw.startswith("secret"):
            return "Secret", obj_name, version
        if obj_type_raw.startswith("key"):
            return "Key", obj_name, version
        if obj_type_raw.startswith("certificate"):
            return "Certificate", obj_name, version
    return None, None, None

def extract_fields(ev: func.EventGridEvent):
    try:
        data = ev.get_json() or {}
    except Exception:
        logging.exception("Failed to parse Event Grid JSON body")
        data = {}

    event_type = getattr(ev, "event_type", None) or data.get("eventType")
    vault = data.get("vaultName")
    obj_type = data.get("objectType")
    obj_name = data.get("objectName")
    version  = data.get("version")

    if not vault:
        vault = parse_from_topic(getattr(ev, "topic", None))

    if not (obj_type and obj_name):
        t, n, v = parse_from_subject(getattr(ev, "subject", None))
        obj_type = obj_type or t
        obj_name = obj_name or n
        version  = version  or v

    return event_type, vault, obj_type, obj_name, version

def main(event: func.EventGridEvent):
    event_type, src_vault, obj_type, obj_name, version = extract_fields(event)
    tgt_vault = os.environ.get("TARGET_VAULT_NAME")

    logging.info(f"KV Replicator triggered. type={event_type} src={src_vault} objType={obj_type} objName={obj_name} version={version} tgt={tgt_vault} subject={getattr(event, 'subject', None)} topic={getattr(event, 'topic', None)}")

    if event_type not in ALLOWED_EVENTS:
        logging.info(f"Ignoring event type: {event_type}")
        return

    if not (src_vault and obj_name and tgt_vault):
        logging.error(f"Missing required fields after fallback. objectName={obj_name}, src={src_vault}, tgt={tgt_vault}")
        return

    try:
        if event_type.endswith("SecretNewVersionCreated"):
            replicate_secret(src_vault, tgt_vault, obj_name, version)
        elif event_type.endswith("KeyNewVersionCreated"):
            replicate_key_metadata(src_vault, tgt_vault, obj_name, version)
        elif event_type.endswith("CertificateNewVersionCreated"):
            replicate_certificate_public(src_vault, tgt_vault, obj_name, version)
        else:
            logging.info(f"Unhandled event type: {event_type}")
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

    logging.info(f"[Secret] {name} replicated to {tgt}. targetVersion={set_resp.properties.version}")

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
        logging.warning(f"[Key] Type {kty} not supported for auto-create. Skipping {name}.")
        return

    if key.properties.tags:
        props = tgt_client.get_key(name).properties
        props.tags = key.properties.tags
        tgt_client.update_key_properties(props)

    logging.info(f"[Key] {name} created on target (comparable key; material not copied).")

def replicate_certificate_public(src: str, tgt: str, name: str, version: str):
    src_client = CertificateClient(kv_url(src), cred)
    tgt_client = CertificateClient(kv_url(tgt), cred)

    cert = src_client.get_certificate_version(name, version)
    tgt_client.import_certificate(name=name, certificate_bytes=cert.cer)

    if cert.properties.tags:
        props = tgt_client.get_certificate(name).properties
        props.tags = cert.properties.tags
        tgt_client.update_certificate_properties(props)

    logging.info(f"[Cert] {name} public certificate replicated to {tgt}.")
