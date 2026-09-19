import sys
from unittest.mock import MagicMock

class MockSessionState(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)
    def __setattr__(self, key, value):
        self[key] = value

mock_st = MagicMock()
mock_st.session_state = MockSessionState()
sys.modules["streamlit"] = mock_st
sys.modules["streamlit.components.v1"] = MagicMock()

mock_oauth2_mod = MagicMock()
sys.modules["httpx_oauth"] = MagicMock()
sys.modules["httpx_oauth.oauth2"] = mock_oauth2_mod

# OAuth2 is used as a class in StreamlitOauth component
class MockOAuth2:
    def __init__(self, *args, **kwargs):
        pass
    async def get_authorization_url(self, *args, **kwargs):
        return "http://example.com/auth"
    async def get_access_token(self, *args, **kwargs):
        return {"access_token": "mock_token"}
    async def refresh_token(self, *args, **kwargs):
        return {"access_token": "mock_refreshed_token"}
    async def revoke_token(self, *args, **kwargs):
        pass

mock_oauth2_mod.OAuth2 = MockOAuth2

sys.modules["dotenv"] = MagicMock()
