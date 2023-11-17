import streamlit as st
from streamlit_oauth import OAuth2Component
from typing import Any, Dict, List, Optional, Tuple, cast
import base64
from httpx_oauth.oauth2 import BaseOAuth2
import os

NOTION_OAUTH2_CLIENT_ID = os.environ.get("NOTION_OAUTH2_CLIENT_ID")
NOTION_OAUTH2_CLIENT_SECRET = os.environ.get("NOTION_OAUTH2_CLIENT_SECRET")
NOTION_OAUTH2_AUTHORIZATION_URL = "https://api.notion.com/v1/oauth/authorize"
NOTION_OAUTH2_TOKEN_URL = "https://api.notion.com/v1/oauth/token"


class NotionOAuth2(BaseOAuth2):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            client_id,
            client_secret,
            NOTION_OAUTH2_AUTHORIZATION_URL,
            NOTION_OAUTH2_TOKEN_URL,
            NOTION_OAUTH2_TOKEN_URL,
            NOTION_OAUTH2_TOKEN_URL,
            **kwargs,
        )

    # override get_access_token to use Notion's custom OAuth2 flow
    async def get_access_token(
        self, code: str, redirect_uri: Optional[str] = None
    ) -> Dict[str, Any]:
        async with self.get_httpx_client() as client:
            data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            }
            basic_auth = self.client_id + ":" + self.client_secret
            # base64 encode the basic auth string
            basic_auth = base64.b64encode(basic_auth.encode("ascii")).decode("ascii")
            headers = {
                "Authorization": f"Basic {basic_auth}",
                "Content-Type": "application/json",
            }
            response = await client.post(self.access_token_endpoint, headers=headers, json=data) 
            if response.status_code != 200:
                raise Exception(response.text)
            response.raise_for_status()
            return cast(Dict[str, Any], response.json())


st.title("Notion OAuth2 Example")
st.write("This example shows how to use the OAuth2 component to authenticate with Notion and get the user's email address.")

notion_client = NotionOAuth2(NOTION_OAUTH2_CLIENT_ID, NOTION_OAUTH2_CLIENT_SECRET)

# create an OAuth2Component instance
oauth2 = OAuth2Component(
    client_id=None,
    client_secret=None,
    authroize_endpoint=None,
    token_endpoint=None,
    refresh_token_endpoint=None,
    revoke_token_endpoint=None,
    client=notion_client,
)

if "notion_token" not in st.session_state:
    # create a button to start the OAuth2 flow
    result = oauth2.authorize_button(
        name="Login with Notion",
        icon="https://www.notion.so/images/favicon.ico",
        redirect_uri="http://localhost:8501",
        scope="user",
        key="notion",
        extras_params={"owner": "user"},
        use_container_width=True,
    )

    if result:
        st.session_state["notion_token"] = result
        st.rerun()
else:
    st.write("You are logged in!")
    st.write(st.session_state["notion_token"])
    st.button("Logout")
    del st.session_state["notion_token"]