import requests

import streamlit as st
from streamlit_oauth import OAuth2Component
import os

st.title("Jira OAuth2 Example")
st.write("This example shows how to use the OAuth2 component to authenticate with a custom OAuth2 provider.")
st.write("For information on how to get Jira oAuth credentials or how to create the oAuth client, you can visit the official Jira documentation: https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/")

JIRA_OAUTH_CLIENT_ID            = os.getenv("JIRA_OAUTH_CLIENT_ID")
JIRA_OAUTH_CLIENT_SECRET        = os.getenv("JIRA_OAUTH_CLIENT_SECRET")
JIRA_OAUTH_AUTHORIZATION_URL    = os.getenv("JIRA_OAUTH_AUTHORIZATION_URL")
JIRA_OAUTH_TOKEN_URL            = os.getenv("JIRA_OAUTH_TOKEN_URL")
JIRA_OAUTH_REDIRECT_URI         = os.getenv("JIRA_OAUTH_REDIRECT_URI")

if "auth" not in st.session_state:
    #  create a button to start the OAuth2 flow
    oauth2_jira = OAuth2Component(
        client_id           = JIRA_OAUTH_CLIENT_ID, 
        client_secret       = JIRA_OAUTH_CLIENT_SECRET, 
        authorize_endpoint  = JIRA_OAUTH_AUTHORIZATION_URL, 
        token_endpoint      = JIRA_OAUTH_TOKEN_URL, 
    )
    result_jira = oauth2_jira.authorize_button(
        name                = "Continue with Jira",
        icon                = "https://jira.atlassian.com/s/-ul0njf/9120008/1rg1jpn/_/jira-favicon-hires.png", 
        redirect_uri        = JIRA_OAUTH_REDIRECT_URI, # This is the redirect URI that you set in the OAuth2 app settings.
        scope               = "read:jira-user",
        key                 = "jira",
        extras_params       = {"audience": "api.atlassian.com", "response_type": "code", "prompt": "consent" }
    )

    # result_jira will receive the following JSON, in which we use the access_token
    # to make requests to the Atlassian API, according to the permissions granted
    # according to the documentation.
    # {
    #     "state": "...",
    #     "code": "...",
    #     "token": {
    #         "access_token": "...",
    #         "expires_in": 3600,
    #         "token_type": "Bearer",
    #         "scope": "read:jira-user",
    #         "expires_at": ...
    #     }
    # }

    if result_jira:
        st.write(result_jira)
        access_token = result_jira["token"]["access_token"]
        st.session_state["auth"] = access_token

        # Optiona: Here you can make calls to the API using the access token, for your purposes.
        url = "https://api.atlassian.com/oauth/token/accessible-resources"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(url, headers = headers)

        if response.status_code == 200:
            st.write(response.json())
        else:
            st.write("Error: Failed to get accessible resources")


    else:
        st.write("You are not logged in!")
        st.stop()

else:
    st.write("You are logged in!")
    st.write(st.session_state["auth"])

