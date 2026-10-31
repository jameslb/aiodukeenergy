"""Regression coverage for the replacement account/list response."""

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from aiodukeenergy import DukeEnergy


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [None, ""])
async def test_multiple_accounts_preserve_ids_and_normalize_defaults(
    missing, monkeypatch
):
    """Electric/gas accounts keep their own routing IDs and meter details."""
    client = DukeEnergy(MagicMock(email="test@example.com", internal_user_id="test"))
    electric = {
        "accountNumber": "electric",
        "primaryBPNumber": "bp-electric",
        "srcSysCd": "LEGACY",
        "srcAcctId": "source-electric",
        "srcAcctId2": "second",
    }
    gas = {
        "accountNumber": "gas",
        "primaryBPNumber": "bp-gas",
        "srcSysCd": missing,
        "srcAcctId": missing,
        "srcAcctId2": missing,
    }
    get_json = AsyncMock(
        side_effect=[
            {"accounts": [electric, gas], "relatedBPNumber": "related"},
            {"meterInfo": [{"serviceType": "ELECTRIC", "serialNum": "E"}]},
            {"meterInfo": [{"serviceType": "GAS", "serialNum": "G"}]},
        ]
    )

    monkeypatch.setattr(client, "_get_json", get_json)
    accounts = await client.get_accounts()

    assert set(accounts) == {"electric", "gas"}
    assert accounts["electric"]["srcAcctId2"] == "second"
    assert accounts["gas"]["srcAcctId2"] == ""
    calls = get_json.call_args_list
    assert str(calls[0].args[0]).endswith("/account/list")
    assert calls[1].args[1] == {
        "email": "test@example.com",
        "srcSysCd": "LEGACY",
        "srcAcctId": "source-electric",
        "primaryBpNumber": "bp-electric",
        "relatedBpNumber": "related",
    }
    assert calls[2].args[1]["srcSysCd"] == "ISU"
    assert calls[2].args[1]["srcAcctId"] == "gas"
    assert calls[2].args[1]["primaryBpNumber"] == "bp-gas"
    assert accounts["gas"]["details"]["meterInfo"][0]["serviceType"] == "GAS"
    assert await client.get_accounts() is accounts
    assert get_json.await_count == 3


@pytest.mark.asyncio
async def test_failed_refresh_keeps_previous_complete_account_cache(monkeypatch):
    """A later details failure must not publish a partially refreshed list."""
    client = DukeEnergy(MagicMock())
    previous = {"old": {"accountNumber": "old"}}
    client._accounts = previous
    get_json = AsyncMock(
        side_effect=[
            {"accounts": [{"accountNumber": "one"}, {"accountNumber": "two"}]},
            {"meterInfo": []},
            aiohttp.ClientConnectionError("synthetic outage"),
        ]
    )
    monkeypatch.setattr(client, "_get_json", get_json)
    with pytest.raises(aiohttp.ClientConnectionError):
        await client.get_accounts(fresh=True)
    assert await client.get_accounts() is previous
