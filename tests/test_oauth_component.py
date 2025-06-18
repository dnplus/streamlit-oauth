import time
import streamlit as st
import pytest
from unittest.mock import AsyncMock

from streamlit_oauth import OAuth2Component, OAuth2, StreamlitOauthError


def test_authorize_button_success(monkeypatch):
    st.session_state.clear()
    client = OAuth2("id", "secret", "auth", "token")
    oauth = OAuth2Component(client=client)

    # Mock async client methods
    monkeypatch.setattr(oauth.client, "get_authorization_url", AsyncMock(return_value="http://auth"))
    monkeypatch.setattr(oauth.client, "get_access_token", AsyncMock(return_value={"access_token": "tok"}))

    # Force deterministic state and component output
    monkeypatch.setattr("streamlit_oauth._generate_state", lambda key=None: "STATE")
    monkeypatch.setattr("streamlit_oauth._authorize_button", lambda **kwargs: {"code": "CODE", "state": "STATE"})

    result = oauth.authorize_button("Login", "http://cb", "scope", key="k")
    assert result["token"]["access_token"] == "tok"
    assert f"state-k" not in st.session_state


def test_authorize_button_state_mismatch(monkeypatch):
    st.session_state.clear()
    client = OAuth2("id", "secret", "auth", "token")
    oauth = OAuth2Component(client=client)

    monkeypatch.setattr(oauth.client, "get_authorization_url", AsyncMock(return_value="http://auth"))
    monkeypatch.setattr(oauth.client, "get_access_token", AsyncMock(return_value={"access_token": "tok"}))
    monkeypatch.setattr("streamlit_oauth._generate_state", lambda key=None: "GOOD")
    monkeypatch.setattr("streamlit_oauth._authorize_button", lambda **kwargs: {"code": "CODE", "state": "BAD"})

    with pytest.raises(StreamlitOauthError):
        oauth.authorize_button("Login", "http://cb", "scope", key="k")


def test_refresh_token_expired(monkeypatch):
    client = OAuth2("id", "secret", "auth", "token")
    oauth = OAuth2Component(client=client)

    monkeypatch.setattr(oauth.client, "refresh_token", AsyncMock(return_value={"access_token": "new"}))

    token = {"access_token": "old", "refresh_token": "r", "expires_at": time.time() - 1}
    result = oauth.refresh_token(token)

    assert result["access_token"] == "new"


def test_revoke_token(monkeypatch):
    client = OAuth2("id", "secret", "auth", "token")
    oauth = OAuth2Component(client=client)
    revoke_mock = AsyncMock()
    monkeypatch.setattr(oauth.client, "revoke_token", revoke_mock)

    assert oauth.revoke_token({"access_token": "abc"}) is True
    revoke_mock.assert_awaited_once()
