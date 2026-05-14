import os
import urllib.parse
import uuid
import pytest
import requests
import requests_unixsocket
from jsonschema import validate, ValidationError

# Initialize requests_unixsocket
requests_unixsocket.monkeypatch()

import json
import base64
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
from pyhpke.consts import Mode

# Helper to load JSON schemas
def load_schema(name):
    path = os.path.join(os.path.dirname(__file__), "schemas", f"{name}.json")
    with open(path) as f:
        return json.load(f)

ERROR_SCHEMA = load_schema("error")
CAPABILITIES_SCHEMA = load_schema("capabilities")
GENERATE_KEY_SCHEMA = load_schema("generate_key")
ENUMERATE_KEYS_SCHEMA = load_schema("enumerate_keys")
DECAPS_RESPONSE_SCHEMA = load_schema("decaps_response")

@pytest.fixture(scope="module")
def wsd_client():
    socket_path = os.environ.get("WSD_SOCKET_PATH", "/run/container_launcher/kmaserver.sock")
    if not os.path.exists(socket_path):
        pytest.skip(f"Socket file not found at {socket_path}. Skipping integration tests.")
    
    session = requests_unixsocket.Session()
    encoded_path = urllib.parse.quote(socket_path, safe="")
    base_url = f"http+unix://{encoded_path}"
    return base_url, session

@pytest.fixture(scope="function")
def valid_key_pair(wsd_client):
    base_url, session = wsd_client
    payload = {
        "algorithm": {
            "type": "kem",
            "params": {
                "kem_id": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"
            }
        },
        "lifespan": 3600
    }
    resp = session.post(f"{base_url}/v1/keys:generate_key", json=payload, timeout=10)
    assert resp.status_code == 200, f"Response: {resp.text}"
    data = resp.json()
    return data["key_handle"]["handle"], data["pub_key"]["public_key"]

@pytest.fixture(scope="function")
def valid_key_handle(valid_key_pair):
    handle, _ = valid_key_pair
    return handle

# --- Get Capabilities Tests ---

def test_get_capabilities_success(wsd_client):
    base_url, session = wsd_client
    resp = session.get(f"{base_url}/v1/capabilities", timeout=10)
    assert resp.status_code == 200, f"Response: {resp.text}"
    validate(instance=resp.json(), schema=CAPABILITIES_SCHEMA)

# --- Generate Key Tests ---

@pytest.mark.parametrize(
    "payload,expected_status,expected_error_subset",
    [
        # Success case (tested separately to validate schema, but included here for status check)
        (
            {
                "algorithm": {"type": "kem", "params": {"kem_id": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},
                "lifespan": 3600
            },
            200,
            None
        ),
        # Sad Case: Missing algorithm
        (
            {"lifespan": 3600},
            400,
            "invalid request" # protovalidate error
        ),
        # Sad Case: Zero lifespan
        (
            {
                "algorithm": {"type": "kem", "params": {"kem_id": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},
                "lifespan": 0
            },
            400,
            "invalid request" # protovalidate error (lifespan gt 0)
        ),
        # Sad Case: Negative lifespan (should fail json unmarshal)
        (
            {
                "algorithm": {"type": "kem", "params": {"kem_id": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},
                "lifespan": -1
            },
            400,
            "invalid request body"
        ),
        # Sad Case: Unsupported algorithm type
        (
            {
                "algorithm": {"type": "signature", "params": {"kem_id": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},
                "lifespan": 3600
            },
            400,
            'unsupported algorithm type: "signature". Only \'kem\' is supported.'
        ),
        # Sad Case: Unsupported KEM algorithm
        (
            {
                "algorithm": {"type": "kem", "params": {"kem_id": "KEM_ALGORITHM_UNSPECIFIED"}},
                "lifespan": 3600
            },
            400,
            "unsupported algorithm: KEM_ALGORITHM_UNSPECIFIED. Supported algorithms: KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"
        ),
    ]
)
def test_generate_key_signature(wsd_client, payload, expected_status, expected_error_subset):
    base_url, session = wsd_client
    resp = session.post(f"{base_url}/v1/keys:generate_key", json=payload, timeout=10)
    assert resp.status_code == expected_status, f"Response: {resp.text}"
    
    if expected_status == 200:
        validate(instance=resp.json(), schema=GENERATE_KEY_SCHEMA)
    else:
        data = resp.json()
        validate(instance=data, schema=ERROR_SCHEMA)
        assert expected_error_subset in data["error"]

# --- Enumerate Keys Tests ---

def test_enumerate_keys_success(wsd_client, valid_key_handle):
    base_url, session = wsd_client
    resp = session.get(f"{base_url}/v1/keys", timeout=10)
    assert resp.status_code == 200, f"Response: {resp.text}"
    data = resp.json()
    validate(instance=data, schema=ENUMERATE_KEYS_SCHEMA)
    # Verify the key we just generated is in the list
    handles = [k["key_handle"]["handle"] for k in data["key_infos"]]
    assert valid_key_handle in handles

# --- Decapsulate Tests ---

@pytest.mark.parametrize(
    "payload_gen_fn,expected_status,expected_error_subset",
    [
        # Missing key_handle
        (
            lambda key: {"ciphertext": {"algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256", "ciphertext": "dGVzdA=="}},
            400,
            "invalid request"
        ),
        # Missing ciphertext
        (
            lambda key: {"key_handle": {"handle": str(uuid.uuid4())}},
            400,
            "invalid request"
        ),
        # Invalid UUID for key handle
        (
            lambda key: {"key_handle": {"handle": "not-a-uuid"}, "ciphertext": {"algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256", "ciphertext": "dGVzdA=="}},
            400,
            "invalid key_handle.handle"
        ),
        # Unsupported KEM algorithm
        (
            lambda key: {"key_handle": {"handle": str(uuid.uuid4())}, "ciphertext": {"algorithm": "KEM_ALGORITHM_UNSPECIFIED", "ciphertext": "dGVzdA=="}},
            400,
            "unsupported ciphertext algorithm: 0"
        ),
        # Empty ciphertext bytes
        (
            lambda key: {"key_handle": {"handle": str(uuid.uuid4())}, "ciphertext": {"algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256", "ciphertext": ""}},
            400,
            "ciphertext.ciphertext must not be empty"
        ),
        # Key not found (valid UUID but non-existent)
        (
            lambda key: {"key_handle": {"handle": str(uuid.uuid4())}, "ciphertext": {"algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256", "ciphertext": "dGVzdA=="}},
            404,
            "KEM key handle not found"
        ),
        # Invalid Ciphertext (triggers decapsulation failure in backend -> 500)
        (
            lambda key: {"key_handle": {"handle": key}, "ciphertext": {"algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256", "ciphertext": "dGVzdA=="}},
            500,
            "failed to decap and seal"
        ),
    ]
)
def test_decapsulate_signature(wsd_client, valid_key_handle, payload_gen_fn, expected_status, expected_error_subset):
    base_url, session = wsd_client
    payload = payload_gen_fn(valid_key_handle)
    resp = session.post(f"{base_url}/v1/keys:decap", json=payload, timeout=10)
    assert resp.status_code == expected_status, f"Response: {resp.text}"
    
    data = resp.json()
    validate(instance=data, schema=ERROR_SCHEMA)
    assert expected_error_subset in data["error"]

def test_decapsulate_success(wsd_client, valid_key_pair):
    base_url, session = wsd_client
    key_handle, pub_key_b64 = valid_key_pair
    
    # 1. Initialize HPKE suite in Python (DHKEM_X25519, HKDF_SHA256, AES256_GCM)
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM)
    kem = suite.kem
    
    pub_key_bytes = base64.b64decode(pub_key_b64)
    kem_pub_key = kem.deserialize_public_key(pub_key_bytes)
    
    # 2. Perform HPKE encapsulation and seal a dummy payload
    # Match Go FFI behavior by passing empty info AAD during context setup
    enc, sender_context = suite.create_sender_context(kem_pub_key, b"")
    
    plaintext = b"authentic-secret-32-bytes-value!" # 32-byte payload
    ciphertext = sender_context.seal(plaintext)
    
    # Base64 encode the encapsulated key (ciphertext)
    enc_b64 = base64.b64encode(enc).decode("utf-8")
    
    # 2. Call WSD decapsulate API
    payload = {
        "key_handle": {"handle": key_handle},
        "ciphertext": {
            "algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256",
            "ciphertext": enc_b64
        }
    }
    
    resp = session.post(f"{base_url}/v1/keys:decap", json=payload, timeout=10)
    assert resp.status_code == 200, f"Response: {resp.text}"
    
    data = resp.json()
    validate(instance=data, schema=DECAPS_RESPONSE_SCHEMA)
    
    returned_secret_b64 = data["shared_secret"]["secret"]
    shared_secret_bytes = base64.b64decode(returned_secret_b64)
    
    # 3. Use the returned KEM shared secret to initialize HPKE receiver context in Python
    # This mimics the receiver context setup using raw KEM secret.
    recipient_context = suite._key_schedule_r(Mode.BASE, shared_secret_bytes, b"", b"", b"")
    
    # 4. Open the ciphertext locally and verify it matches the original plaintext!
    decrypted = recipient_context.open(ciphertext)
    assert decrypted == plaintext, f"Payload mismatch! Expected: {plaintext}, Got: {decrypted}"

# --- Destroy Key Tests ---

def test_destroy_key_success(wsd_client, valid_key_handle):
    base_url, session = wsd_client
    payload = {"key_handle": {"handle": valid_key_handle}}
    
    # Destroy
    resp = session.post(f"{base_url}/v1/keys:destroy", json=payload, timeout=10)
    assert resp.status_code == 204, f"Response: {resp.text}"
    assert resp.text == "" # 204 should have no body
    
    # Verify it is gone (enumerate)
    resp_enum = session.get(f"{base_url}/v1/keys", timeout=10)
    assert resp_enum.status_code == 200, f"Response: {resp_enum.text}"
    handles = [k["key_handle"]["handle"] for k in resp_enum.json()["key_infos"]]
    assert valid_key_handle not in handles

@pytest.mark.parametrize(
    "payload,expected_status,expected_error_subset",
    [
        # Missing key_handle
        (
            {},
            400,
            "invalid request"
        ),
        # Invalid UUID
        (
            {"key_handle": {"handle": "not-a-uuid"}},
            400,
            "invalid key handle"
        ),
        # Key not found (valid UUID but non-existent)
        (
            {"key_handle": {"handle": str(uuid.uuid4())}},
            404,
            "KEM key handle not found"
        ),
    ]
)
def test_destroy_key_signature_errors(wsd_client, payload, expected_status, expected_error_subset):
    base_url, session = wsd_client
    resp = session.post(f"{base_url}/v1/keys:destroy", json=payload, timeout=10)
    assert resp.status_code == expected_status, f"Response: {resp.text}"
    
    data = resp.json()
    validate(instance=data, schema=ERROR_SCHEMA)
    assert expected_error_subset in data["error"]
