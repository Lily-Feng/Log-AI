import pytest

from javalogai.scrub.scrubber import Scrubber, luhn_valid


@pytest.mark.parametrize("pan", ["4111111111111111", "5500005555555559", "378282246310005"])
def test_luhn_accepts_real_card_shapes(pan):
    assert luhn_valid(pan)


@pytest.mark.parametrize("bad", ["4029183746152839", "1234567890123", "", "abcd", "411111111111111a"])
def test_luhn_rejects_non_cards(bad):
    assert not luhn_valid(bad)


def test_pan_redacted_with_separators():
    for text in ["card 4111111111111111", "card 4111 1111 1111 1111", "card 4111-1111-1111-1111"]:
        assert Scrubber().scrub(text).text == "card [PAN]"


def test_luhn_invalid_long_number_is_left_alone():
    # A 16-digit order id must survive: over-redaction destroys debuggability.
    r = Scrubber().scrub("orderId=4029183746152839 completed")
    assert "4029183746152839" in r.text
    assert "pan" not in r.hits


def test_digit_run_inside_hex_trace_id_is_not_a_pan():
    # Regression: hex ids contain long digit substrings that pass Luhn ~1 in 10.
    # Matching them raised false PCI alarms and corrupted the trace id.
    trace = "c69589cd62e07957166693998c2eb4ef"
    r = Scrubber().scrub(f"[payment-svc,{trace},343a50db67a3c30c] processing")
    assert trace in r.text
    assert "pan" not in r.hits


def test_hit_counts_reflect_actual_redactions_not_matches():
    r = Scrubber().scrub("card 4111111111111111 orderId=4029183746152839")
    assert r.hits["pan"] == 1


def test_pan_keep_last4_for_payments_triage():
    assert Scrubber(pan_keep_last4=True).scrub("card 4111111111111111").text == "card [PAN:...1111]"


def test_secrets_and_tokens():
    s = Scrubber()
    assert s.scrub("password: hunter2").text == "password: [REDACTED]"
    assert s.scrub("token=abc123").text == "token=[REDACTED]"
    assert s.scrub("access_token=xyz").text == "access_token=[REDACTED]"
    assert "[JWT]" in s.scrub("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc").text


def test_similar_words_are_not_redacted():
    assert Scrubber().scrub("tokenizer=drain3 ready").text == "tokenizer=drain3 ready"


def test_optional_rules_are_off_unless_enabled():
    assert Scrubber().scrub("from 10.2.3.4").text == "from 10.2.3.4"
    assert Scrubber(enable_optional=("ipv4",)).scrub("from 10.2.3.4").text == "from [IP]"


def test_disable_rule():
    assert Scrubber(disable=("email",)).scrub("a@b.com").text == "a@b.com"


def test_totals_accumulate_and_track_flag_prevents_double_counting():
    s = Scrubber()
    s.scrub("card 4111111111111111")
    s.scrub("card 4111111111111111", track=False)
    assert s.totals["pan"] == 1


def test_over_redaction_is_the_intended_failure_direction():
    # Real Hadoop logs contain `Token: Token { kind: ContainerToken ... }`. The
    # word after `Token:` is a type name, not a credential, and it is redacted
    # anyway. That is deliberate: under-redacting a real secret is far worse
    # than redacting a harmless word, so the rule is not loosened to fix this.
    r = Scrubber().scrub("Token: Token { kind: ContainerToken }")
    assert r.text.startswith("Token: [REDACTED]")
    assert r.hits["secret_kv"] == 1
