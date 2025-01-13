import streamlit as st
from streamlit_oauth import OAuth2Component
import os

st.title("Yandex OAuth2 Example")
st.write("This example shows how to use the OAuth2 component to authenticate with a custom OAuth2 provider.")
st.write("For information on how to get Yandex oAuth credentials or how to create the oAuth client, you can visit the official Jira documentation: https://yandex.ru/dev/id/doc/en/index.html")

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Set environment variables
AUTHORIZE_URL     = 'https://oauth.yandex.ru/authorize'
TOKEN_URL         = 'https://oauth.yandex.ru/token'
REFRESH_TOKEN_URL = 'https://oauth.yandex.ru/token'
REVOKE_TOKEN_URL  = 'https://oauth.yandex.ru/revoke_token'
CLIENT_ID         = os.environ.get('CLIENT_ID')
CLIENT_SECRET     = os.environ.get('CLIENT_SECRET')
REDIRECT_URI      = 'http://localhost:8501'
SCOPE             = ''

# Create OAuth2Component instance
oauth2 = OAuth2Component(
    client_id              = CLIENT_ID, 
    client_secret          = CLIENT_SECRET, 
    authorize_endpoint     = AUTHORIZE_URL, 
    token_endpoint         = TOKEN_URL, 
    refresh_token_endpoint = REFRESH_TOKEN_URL,
    revoke_token_endpoint  = REVOKE_TOKEN_URL,
    client                 = None,
)

# Check if token exists in session state
if 'token' not in st.session_state:
    # If not, show authorize button
    result = oauth2.authorize_button("Authorize", REDIRECT_URI, SCOPE)
    if result and 'token' in result:
        # If authorization successful, save token in session state
        st.session_state.token = result.get('token')
        st.rerun()
else:
    # If token exists in session state, show the token
    token = st.session_state['token']
    st.json(token)
    if st.button("Refresh Token"):
        # If refresh token button is clicked, refresh the token
        token = oauth2.refresh_token(token)
        st.session_state.token = token
        st.rerun()
