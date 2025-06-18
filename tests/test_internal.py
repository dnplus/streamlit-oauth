import streamlit as st
from streamlit_oauth import _generate_state, _generate_pkce_pair
import pytest


def test_generate_state_same_key():
    st.session_state.clear()
    s1 = _generate_state(key="a")
    s2 = _generate_state(key="a")
    assert s1 == s2


def test_generate_state_different_key():
    st.session_state.clear()
    s1 = _generate_state(key="a")
    s2 = _generate_state(key="b")
    assert s1 != s2


def test_generate_pkce_pair_same_key():
    st.session_state.clear()
    p1 = _generate_pkce_pair("S256", key="x")
    p2 = _generate_pkce_pair("S256", key="x")
    assert p1 == p2
    assert len(p1) == 2


def test_generate_pkce_pair_invalid():
    st.session_state.clear()
    with pytest.raises(Exception):
        _generate_pkce_pair("plain", key="x")
