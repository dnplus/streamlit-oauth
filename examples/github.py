import streamlit as st
from streamlit_oauth import OAuth2Component
from httpx_oauth.clients.github import GitHubOAuth2
import os

st.title("Github Client Example")
st.write("To generate an OAuth app, go to this link: https://github.com/settings/developers. There, create a new app, and copy its credentials into the environment. Then, add the url `http://localhost:8501` into the auth callback prompt. Now you are set!")
st.write("For more information on scopes selection, go to the github documentation: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps")

# create an OAuth2Component instance
CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
GITHUB_SCOPES = [
    # "public_repo",      # Full control and access to public repos only

    # From here, permissions refer to both public and private repos always
    "repo:status",      # Commit statuses access
    "repo_deployment",  # Deployment statuses access
    "repo:invite",      # Repo collaboration invite accept/decline access
    "security_events",  # Security events through code scan access
    # "repo",             # Full control and access to repos

    # "admin:org_hook",   # R/W, ping, and delete access to owned hooks at orgs
    # "gist",             # Write access to owner's gists
    # "notifications",    # Read access to notif and full access to thread subscriptions
    # "user",             # Gives read:user, user:email, and user:follow access
    # "project",          # R/W access to projects, read:project for read-only
    # "delete_repo",      # Access to repo deletion. Must have admin access to the repo
    # "codespace",        # Full access to create and manage codespaces
    # "workflow",         # Full access to GH actions workflow files
    # "read:audit_log",   # Read access to audit logs data

    # Here permissions can be limited to write or read instead, example: "read:org"
    # "admin:repo_hook",  # R/W, ping, and delete access to repo hooks
    # "admin:org",        # Full control and access to orgs, its teams and members
    # "admin:public_key", # R/W and delete access to public keys
    # "admin:gpg_key",    # R/W and delete access to GPG keys
    # "delete:packages",  # Delete access to packages from GH Packages
]

client = GitHubOAuth2(CLIENT_ID, CLIENT_SECRET, GITHUB_SCOPES)

# create a button to start the OAuth2 flow
oauth2 = OAuth2Component(client=client)

if "github_credentials" not in st.session_state:
    result = oauth2.authorize_button(
        name="Login with Github",
        icon="https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png",
        redirect_uri="http://localhost:8501",
        scope=" ".join(GITHUB_SCOPES),
        key="github",
        extras_params={"prompt": "none"},
        use_container_width=True,
    )

    if result:
        st.session_state["github_credentials"] = result
        st.rerun()
else:
    st.write("You are logged in!")
    st.write(st.session_state["github_credentials"])
    if st.button("Logout"):
        del st.session_state["github_credentials"]
        st.rerun()
