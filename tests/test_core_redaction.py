from l0vi0x.core.redaction import redact
from l0vi0x.core.store import Store


def test_redaction_covers_provider_secrets_and_private_keys_without_token_false_positive():
    text = "api_key=secret-value\npassword=admin123\nsk-ant-api03-abcdefghijklmnopqrst\ngsk_abcdefghijklmnopqrst\nnvapi-abcdefghijklmnop\nAIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123\nprivate_key=0x" + "a" * 64 + "\nurl=https://eth-mainnet.g.alchemy.com/v2/abcdefghijklmnop\ntoken: USDC"
    redacted = redact(text)
    for secret in ["secret-value", "admin123", "sk-ant-api03-abcdefghijklmnopqrst", "gsk_abcdefghijklmnopqrst", "nvapi-abcdefghijklmnop", "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123", "0x" + "a" * 64, "abcdefghijklmnop"]:
        assert secret not in redacted
    assert "token: USDC" in redacted


def test_persistence_redacts_event_payloads_and_entity_bodies():
    store = Store(":memory:")
    store.record_event("hypothesis", "H-1", {"kind": "hyp_created", "notes": "api_key=topsecret"})
    store.create_hypothesis({"id": "H-2", "claim": "private_key=0x" + "b" * 64})
    assert "topsecret" not in store.events[0]["payload"]["notes"]
    assert "b" * 64 not in store.get("hypothesis", "H-2")["claim"]
    store.close()
