import base64
import json
import logging
import os
from typing import Dict, Optional

import streamlit as st
from streamlit_oauth import OAuth2Component, StreamlitOauthError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="Google OAuth Example",
    page_icon="🔐",
    initial_sidebar_state="expanded"
)

st.title("Google OIDC Example")
st.write("This example demonstrates authenticating with Google OAuth2 and retrieving user information from the ID token.")

# OAuth configuration
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
REDIRECT_URI = "http://localhost:8501"  # Your app's redirect URI


def parse_id_token(id_token: str) -> Dict:
    """
    Parse and decode JWT ID token from Google OAuth.
    
    Args:
        id_token: JWT token string
        
    Returns:
        Dict containing the token payload
    """
    try:
        # Extract the payload part of the JWT (second part)
        payload = id_token.split(".")[1]
        
        # Add padding if needed
        payload += "=" * (-len(payload) % 4)
        
        # Decode and parse as JSON
        decoded = base64.b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        logger.error(f"Error parsing ID token: {e}")
        st.error(f"Failed to parse ID token: {e}")
        return {}


def display_user_info(user_info: Dict) -> None:
    """
    Display user information from the ID token in a nice format.
    
    Args:
        user_info: Dictionary containing user data from ID token
    """
    if not user_info:
        return
        
    # Create columns for profile layout
    col1, col2 = st.columns([1, 3])
    
    # Display profile picture if available
    if "picture" in user_info:
        col1.image(user_info["picture"], width=100)
    
    # Display user details
    col2.subheader(user_info.get("name", "Unknown User"))
    col2.write(f"📧 Email: {user_info.get('email', 'Not available')}")
    
    if user_info.get("email_verified"):
        col2.success("✓ Email verified")
    
    # Display additional info in an expander
    with st.expander("More Details"):
        st.json(user_info)


# Main app logic
if "auth" not in st.session_state:
    try:
        if not CLIENT_ID or not CLIENT_SECRET:
            st.warning("⚠️ Google OAuth credentials are not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.")
            st.stop()
            
        # Create OAuth component with authlib
        oauth2 = OAuth2Component(
            CLIENT_ID, 
            CLIENT_SECRET, 
            AUTHORIZE_ENDPOINT, 
            TOKEN_ENDPOINT, 
            TOKEN_ENDPOINT, 
            REVOKE_ENDPOINT
        )
        
        # Show the authorize button
        with st.container():
            st.write("Please authenticate with your Google account:")
            result = oauth2.authorize_button(
                name="Continue with Google",
                icon="https://www.google.com/favicon.ico",
                redirect_uri=REDIRECT_URI,
                scope="openid email profile",
                key="google",
                extra_params={"prompt": "consent", "access_type": "offline"},
                use_container_width=True,
                pkce='S256',
            )
        
        # Process authorization result
        if result:
            if "token" in result and "id_token" in result["token"]:
                # Parse user info from ID token
                id_token = result["token"]["id_token"]
                
                # If using authlib, we might have the payload already
                if "id_token_payload" in result["token"]:
                    user_info = json.loads(result["token"]["id_token_payload"])
                else:
                    user_info = parse_id_token(id_token)
                
                # Store authentication data in session
                st.session_state["auth"] = user_info.get("email")
                st.session_state["user_info"] = user_info
                st.session_state["token"] = result["token"]
                
                # Refresh the page to show authenticated state
                st.rerun()
            elif "error" in result:
                st.error(f"Authentication error: {result.get('error')}")
    except StreamlitOauthError as e:
        st.error(f"OAuth Error: {str(e)}")
    except Exception as e:
        logger.exception("Unexpected error during authentication")
        st.error(f"Unexpected error: {str(e)}")
else:
    # User is authenticated - show profile and options
    st.success("✅ You are logged in!")
    
    # Display user profile
    if "user_info" in st.session_state:
        display_user_info(st.session_state["user_info"])
    else:
        st.write(f"Logged in as: {st.session_state['auth']}")
    
    # Token management
    with st.expander("Access Token Information"):
        st.json(st.session_state["token"])
        
        col1, col2 = st.columns(2)
        
        if col1.button("Refresh Token"):
            try:
                oauth2 = OAuth2Component(
                    CLIENT_ID, CLIENT_SECRET, AUTHORIZE_ENDPOINT, 
                    TOKEN_ENDPOINT, TOKEN_ENDPOINT, REVOKE_ENDPOINT
                )
                token = oauth2.refresh_token(st.session_state["token"], force=True)
                st.session_state["token"] = token
                st.success("Token refreshed successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Error refreshing token: {str(e)}")
    
    # Logout button
    if st.button("Logout", type="primary"):
        try:
            # Attempt to revoke the token
            oauth2 = OAuth2Component(
                CLIENT_ID, CLIENT_SECRET, AUTHORIZE_ENDPOINT, 
                TOKEN_ENDPOINT, TOKEN_ENDPOINT, REVOKE_ENDPOINT
            )
            oauth2.revoke_token(st.session_state["token"])
            
            # Clear session state
            for key in ["auth", "token", "user_info"]:
                if key in st.session_state:
                    del st.session_state[key]
                    
            st.rerun()
        except Exception as e:
            logger.warning(f"Error during logout: {e}")
            # Force logout even if revocation fails
            for key in ["auth", "token", "user_info"]:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()