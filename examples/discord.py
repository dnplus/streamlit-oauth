import streamlit as st
from streamlit_oauth import OAuth2Component
from httpx_oauth.clients.discord import DiscordOAuth2
import os
# import logging

# logging.basicConfig(level=logging.DEBUG)

st.title("OAuth2 Client Example")

st.write("This example shows how to use the OAuth2 component to authenticate with a custom OAuth2 provider.")

# create an OAuth2Component instance
CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "1174640935091568641")
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "LvO_CXE6tq2icKSrzKrwvx0Ujp57h2YN")
client = DiscordOAuth2(CLIENT_ID, CLIENT_SECRET)

# create a button to start the OAuth2 flow
oauth2 = OAuth2Component(None, None, None, None, None, None, client=client)

if "discord_token" not in st.session_state:
    result = oauth2.authorize_button(
        name="Login with Discord",
        redirect_uri="http://localhost:8501",
        scope="identify",
        key="discord",
        extras_params={"prompt": "none"},
        use_container_width=True,
    )

    if result:
        st.session_state["discord_token"] = result
        st.rerun()
else:
    st.write("You are logged in!")
    st.write(st.session_state["discord_token"])
    st.button("Logout")
    del st.session_state["discord_token"]