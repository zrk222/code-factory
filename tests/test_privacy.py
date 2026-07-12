from __future__ import annotations

import pytest

from factoryline.privacy import (
    PrivacyError,
    bbs_status,
    issue_bbs_credential,
    merkle_disclosure,
    verify_merkle_disclosure,
    zkvm_pilot_status,
)


def test_merkle_disclosure_proves_one_leaf_without_disclosing_siblings():
    disclosure = merkle_disclosure(["a" * 64, "b" * 64, "c" * 64], "b" * 64)
    assert verify_merkle_disclosure(disclosure) is True
    assert "c" * 64 not in str(disclosure)
    disclosure["leaf"] = "d" * 64
    assert verify_merkle_disclosure(disclosure) is False


def test_merkle_rejects_unknown_leaf():
    with pytest.raises(PrivacyError) as error:
        merkle_disclosure(["a" * 64], "b" * 64)
    assert error.value.code == "E_LEAF_NOT_FOUND"


def test_optional_cryptographic_backends_fail_closed():
    assert bbs_status()["available"] is False
    assert zkvm_pilot_status()["available"] is False
    with pytest.raises(PrivacyError) as error:
        issue_bbs_credential()
    assert error.value.code == "E_BBS_UNAVAILABLE"
