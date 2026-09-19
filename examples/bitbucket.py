import httpx
import streamlit as st
from streamlit_oauth import OAuth2Component
import os

st.title("Bitbucket OAuth2 Example")
st.write("This example shows how to use the OAuth2 component to authenticate with a custom OAuth2 provider.")
st.write("For information on how to get Bitbucket oAuth credentials or how to create the oAuth client, you can visit the official Bitbucket documentation: https://developer.atlassian.com/cloud/bitbucket/oauth-2/")

BITBUCKET_OAUTH_CLIENT_ID         = os.getenv("BITBUCKET_OAUTH_CLIENT_ID")
BITBUCKET_OAUTH_CLIENT_SECRET     = os.getenv("BITBUCKET_OAUTH_CLIENT_SECRET")
BITBUCKET_OAUTH_AUTHORIZATION_URL = os.getenv("BITBUCKET_OAUTH_AUTHORIZATION_URL")
BITBUCKET_OAUTH_TOKEN_URL         = os.getenv("BITBUCKET_OAUTH_TOKEN_URL")
BITBUCKET_OAUTH_REDIRECT_URI      = os.getenv("BITBUCKET_OAUTH_REDIRECT_URI")

@st.cache_data(show_spinner="Fetching workspaces...")
def get_workspaces(access_token):
    url = "https://api.bitbucket.org/2.0/workspaces"
    headers = {"Authorization": f"Bearer {access_token}"}
    with httpx.Client() as client:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

if "auth" not in st.session_state:
    oauth2_bitbucket = OAuth2Component(
        client_id           = BITBUCKET_OAUTH_CLIENT_ID,
        client_secret       = BITBUCKET_OAUTH_CLIENT_SECRET, 
        authorize_endpoint  = BITBUCKET_OAUTH_AUTHORIZATION_URL, 
        token_endpoint      = BITBUCKET_OAUTH_TOKEN_URL, 
    )
    result_bitbucket = oauth2_bitbucket.authorize_button(
        name                = "Continue with Bitbucket",
        icon                = "https://wac-cdn.atlassian.com/assets/img/favicons/bitbucket/favicon-32x32.png",
        redirect_uri        = BITBUCKET_OAUTH_REDIRECT_URI,
        scope               = "",
        key                 = "bitbucket",
        extras_params       = {"prompt": "consent", "access_type": "offline"},
    )

    if result_bitbucket:
        st.write(result_bitbucket)
        access_token = result_bitbucket["token"]["access_token"]
        st.session_state["auth"] = access_token

        # Optiona: Here you can make calls to the API using the access token, for your purposes.
        # This example uses the workspaces API to get the list of workspaces.
        try:
            workspaces = get_workspaces(access_token)
            st.write(workspaces)
        except Exception as e:
            st.error(f"Error: Failed to get workspaces: {e}")

    else:
        st.write("You are not logged in!")
        st.stop()

else:
    st.write("You are logged in!")
    st.write(st.session_state["auth"])

    if st.button("Fetch Workspaces"):
        try:
            workspaces = get_workspaces(st.session_state["auth"])
            st.write(workspaces)
        except Exception as e:
            st.error(f"Error: Failed to get workspaces: {e}")
