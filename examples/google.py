import streamlit as st
from streamlit_oauth import OAuth2Component
from httpx_oauth.clients.google import GoogleOAuth2
import os
import base64
import json

# import logging
# logging.basicConfig(level=logging.INFO)

st.title("Google OIDC Example")
st.write("This example shows how to use the OAuth2 component to authenticate with a Google OAuth2 and get email from id_token.")

# create an OAuth2Component instance
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

if "auth" not in st.session_state:
    # create a button to start the OAuth2 flow
    client = GoogleOAuth2(CLIENT_ID, CLIENT_SECRET)
    oauth2 = OAuth2Component(None, None, None, None, None, None, client=client)
    result = oauth2.authorize_button(
        name="Continue with Google",
        icon="https://www.google.com.tw/favicon.ico",
        redirect_uri="http://localhost:8501",
        scope="openid email profile",
        key="google",
        use_container_width=True,
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
        st.rerun()
else:
    st.write("You are logged in!")
    st.write(st.session_state["auth"])
    st.button("Logout")
    del st.session_state["auth"]