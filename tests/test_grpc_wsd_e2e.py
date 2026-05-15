import os
import base64
import uuid
import pytest
import requests
import requests_unixsocket

# Enable requests to use unix sockets
requests_unixsocket.monkeypatch()

SOCKET_PATH = os.environ.get("SOCKET_PATH", "/tmp/wsd-grpc-e2e.sock")
# requests_unixsocket expects url-encoded path for the host
SOCKET_URL_ENCODED = requests.utils.quote(SOCKET_PATH, safe="")
BASE_URL = f"http+unix://{SOCKET_URL_ENCODED}"


@pytest.fixture(scope="module")
def session():
    """Create a requests session with unix socket support."""
    s = requests_unixsocket.Session()
    return s


def test_capabilities(session):
    """Step 1: GET /v1/capabilities -> 200, mentions DHKEM_X25519"""
    resp = session.get(f"{BASE_URL}/v1/capabilities")
    resp.raise_for_status()
    data = resp.json()

    algos = [
        algo["algorithm"]["params"]["kem_id"]
        for algo in data.get("supported_algorithms", [])
    ]
    assert "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256" in algos


@pytest.fixture(scope="module")
def key_handle(session):
    """Step 2: POST /v1/keys:generate_key -> 200, returns UUID handle"""
    req = {
        "algorithm": {
            "type": "kem",
            "params": {"kem_id": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"},
        },
        "lifespan": 3600,
    }
    resp = session.post(f"{BASE_URL}/v1/keys:generate_key", json=req)
    resp.raise_for_status()
    data = resp.json()

    handle = data.get("key_handle", {}).get("handle")
    assert handle is not None
    # Check if it looks like a valid UUID
    try:
        uuid.UUID(handle)
    except ValueError:
        pytest.fail(f"Handle is not a valid UUID: {handle}")

    # Return handle for other tests, and ensure cleanup afterwards
    yield handle

    # Teardown: ensure the key is destroyed at the end (just in case the destroy test failed)
    session.post(f"{BASE_URL}/v1/keys:destroy", json={"key_handle": {"handle": handle}})


def test_enumerate_contains_key(session, key_handle):
    """Step 3: GET /v1/keys -> 200, contains our handle"""
    resp = session.get(f"{BASE_URL}/v1/keys")
    resp.raise_for_status()
    data = resp.json()

    handles = [k["key_handle"]["handle"] for k in data.get("key_infos", [])]
    assert key_handle in handles


def test_decap_bogus_ciphertext(session, key_handle):
    """Step 4: POST /v1/keys:decap with bogus ciphertext -> 5xx (gRPC error propagated)"""
    req = {
        "key_handle": {"handle": key_handle},
        "ciphertext": {
            "algorithm": "KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256",
            "ciphertext": base64.b64encode(b"bogus-ciphertext-for-e2e-test").decode(
                "utf-8"
            ),
        },
        "aad": "",
    }
    resp = session.post(f"{BASE_URL}/v1/keys:decap", json=req)
    # We expect an error (specifically, a 500 or 400 depending on how gRPC error maps)
    # The bash script asserted status != 200 and != 204
    assert resp.status_code not in (200, 204)


def test_destroy_and_verify(session, key_handle):
    """Steps 5, 6, 7: Destroy key, verify it's gone, and verify second destroy gives 404"""
    # Step 5: POST /v1/keys:destroy -> 204
    req = {"key_handle": {"handle": key_handle}}
    resp = session.post(f"{BASE_URL}/v1/keys:destroy", json=req)
    assert resp.status_code == 204

    # Step 6: GET /v1/keys -> 200, does NOT contain our handle
    resp2 = session.get(f"{BASE_URL}/v1/keys")
    resp2.raise_for_status()
    handles = [k["key_handle"]["handle"] for k in resp2.json().get("key_infos", [])]
    assert key_handle not in handles

    # Step 7: Second destroy on the same key -> 404 (mapping gone)
    resp3 = session.post(f"{BASE_URL}/v1/keys:destroy", json=req)
    assert resp3.status_code == 404
