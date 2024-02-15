import streamlit as st
from streamlit_oauth import OAuth2Component
import os
import base64
import json

# import logging
# logging.basicConfig(level=logging.INFO)

st.title("KINDE OIDC Example")
st.write("This example shows how to use the raw OAuth2 component to authenticate with Kinde (kinde.com)")

# create an OAuth2Component instance
CLIENT_ID = os.environ.get("KINDE_CLIENT_ID")
KINDE_DOMAIN = os.environ.get("KINDE_DOMAIN")
AUTHORIZE_ENDPOINT = f"https://{KINDE_DOMAIN}/oauth2/auth"
TOKEN_ENDPOINT = f"https://{KINDE_DOMAIN}/oauth2/token"
REVOKE_ENDPOINT = f"https://{KINDE_DOMAIN}/oauth2/revoke"


if "auth" not in st.session_state:
    # create a button to start the OAuth2 flow
    oauth2 = OAuth2Component(client_id=CLIENT_ID, authorize_endpoint=AUTHORIZE_ENDPOINT, token_endpoint=TOKEN_ENDPOINT, refresh_token_endpoint=TOKEN_ENDPOINT, revoke_token_endpoint=REVOKE_ENDPOINT)
    result = oauth2.authorize_button(
        name="Continue with Kinde",
        icon="https://kinde.com/icon.svg",
        redirect_uri="http://localhost:8501",
        scope="openid email profile",
        key="kinde",
        use_container_width=True,
        pkce='S256',
    )
    
    if result:
        st.write(result)
        # decode the id_token jwt and get the user's email address
        id_token = result["token"]["id_token"]
        # verify the signature is an optional step for security
        payload = id_token.split(".")[1]
        # add padding to the payload if needed
        payload += "=" * (-len(payload) % 4)
        payload = json.loads(base64.b64decode(payload))
        email = payload["email"]
        st.session_state["auth"] = email
        st.session_state["token"] = result["token"]
        st.rerun()
else:
    st.write("You are logged in!")
    st.write(st.session_state["auth"])
    st.write(st.session_state["token"])
    if st.button("Logout"):
        del st.session_state["auth"]
        del st.session_state["token"]