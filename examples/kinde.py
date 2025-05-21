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
    page_title="Kinde OAuth Example",
    page_icon="🔐",
    initial_sidebar_state="expanded"
)

st.title("Kinde OIDC Example")
st.write("This example demonstrates how to authenticate with Kinde (kinde.com) using the OAuth2 component.")

# OAuth configuration
CLIENT_ID = os.environ.get("KINDE_CLIENT_ID")
KINDE_DOMAIN = os.environ.get("KINDE_DOMAIN")
AUTHORIZE_ENDPOINT = f"https://{KINDE_DOMAIN}/oauth2/auth"
TOKEN_ENDPOINT = f"https://{KINDE_DOMAIN}/oauth2/token"
REVOKE_ENDPOINT = f"https://{KINDE_DOMAIN}/oauth2/revoke"
REDIRECT_URI = "http://localhost:8501"  # Your app's redirect URI


def base64url_decode(input_str: str) -> bytes:
    """
    Decode base64url encoded string.
    
    Args:
        input_str: base64url encoded string
        
    Returns:
        Decoded bytes
    """
    # Make input length a multiple of 4 by adding padding
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)


def parse_jwt(token: str) -> Dict:
    """
    Parse JWT token into its component parts.
    
    Args:
        token: JWT token string
        
    Returns:
        Dict with header, payload, and signature
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split('.')
        
        header = json.loads(base64url_decode(header_b64).decode('utf-8'))
        payload = json.loads(base64url_decode(payload_b64).decode('utf-8'))
        
        return {
            "header": header,
            "payload": payload,
            "signature": signature_b64  # Raw signature part
        }
    except Exception as e:
        logger.error(f"Error parsing JWT: {e}")
        return {"error": str(e)}


def display_user_info(user_info: Dict) -> None:
    """
    Display user information from the ID token in a nice format.
    
    Args:
        user_info: Dictionary containing user data from ID token
    """
    if not user_info or "error" in user_info:
        st.error(f"Failed to parse user info: {user_info.get('error', 'Unknown error')}")
        return
        
    # Create columns for profile layout
    col1, col2 = st.columns([1, 3])
    
    # Display user details
    col2.subheader(user_info.get("name", "Unknown User"))
    col2.write(f"📧 Email: {user_info.get('email', 'Not available')}")
    
    if user_info.get("email_verified"):
        col2.success("✓ Email verified")
    
    # Display organization info if available
    if "org_code" in user_info:
        col2.write(f"🏢 Organization: {user_info.get('org_name', user_info['org_code'])}")
    
    # Display additional info in an expander
    with st.expander("Token Details"):
        st.json(user_info)


# Main app logic
if "auth" not in st.session_state:
    try:
        if not CLIENT_ID or not KINDE_DOMAIN:
            st.warning("⚠️ Kinde credentials are not configured. Please set KINDE_CLIENT_ID and KINDE_DOMAIN environment variables.")
            st.stop()
            
        # Create OAuth component with authlib
        oauth2 = OAuth2Component(
            client_id=CLIENT_ID,
            authorize_endpoint=AUTHORIZE_ENDPOINT,
            token_endpoint=TOKEN_ENDPOINT,
            refresh_token_endpoint=TOKEN_ENDPOINT,
            revoke_token_endpoint=REVOKE_ENDPOINT,
            token_endpoint_auth_method="client_secret_post"
        )
        
        # Show the authorize button
        with st.container():
            st.write("Please authenticate with your Kinde account:")
            result = oauth2.authorize_button(
                name="Continue with Kinde",
                icon="https://kinde.com/icon.svg",
                redirect_uri=REDIRECT_URI,
                scope="openid email profile offline",
                key="kinde",
                use_container_width=True,
                pkce='S256',
            )
        
        # Process authorization result
        if result:
            st.write(result)

            if "token" in result and "id_token" in result["token"]:
                # Get the ID token
                id_token = result["token"]["id_token"]
                
                # Parse the token using our helper function
                parsed_token = parse_jwt(id_token)
                
                if "error" not in parsed_token:
                    # Store user info in session state
                    user_info = parsed_token["payload"]
                    email = user_info.get("email", "unknown")
                    
                    st.session_state["auth"] = email
                    st.session_state["user_info"] = user_info
                    st.session_state["token"] = result["token"]
                    st.rerun()
                else:
                    st.error(f"Failed to parse token: {parsed_token['error']}")
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
        
        if st.button("Refresh Token"):
            try:
                oauth2 = OAuth2Component(
                    client_id=CLIENT_ID,
                    authorize_endpoint=AUTHORIZE_ENDPOINT,
                    token_endpoint=TOKEN_ENDPOINT,
                    refresh_token_endpoint=TOKEN_ENDPOINT,
                    revoke_token_endpoint=REVOKE_ENDPOINT,
                    token_endpoint_auth_method="client_secret_post"
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
                client_id=CLIENT_ID,
                authorize_endpoint=AUTHORIZE_ENDPOINT,
                token_endpoint=TOKEN_ENDPOINT,
                refresh_token_endpoint=TOKEN_ENDPOINT,
                revoke_token_endpoint=REVOKE_ENDPOINT,
                token_endpoint_auth_method="client_secret_post"
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