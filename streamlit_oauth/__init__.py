import os
import asyncio
import base64
import hashlib
import logging
import secrets
import time
import uuid
from typing import Dict, List, Optional, Tuple, Union, Any

import streamlit as st
import streamlit.components.v1 as components
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2.rfc7636 import create_s256_code_challenge

# Configure logging
logger = logging.getLogger(__name__)

# _RELEASE = True
_RELEASE = False

if not _RELEASE:
  _authorize_button = components.declare_component(
    "authorize_button",
    url="http://localhost:3000",  # vite dev server port
  )
else:
  parent_dir = os.path.dirname(os.path.abspath(__file__))
  build_dir = os.path.join(parent_dir, "frontend/dist")
  _authorize_button = components.declare_component("authorize_button", path=build_dir)


class StreamlitOauthError(Exception):
  """
  Exception raised from streamlit-oauth.
  
  This exception is raised when there is an error in the OAuth2 flow.
  """


def _generate_state(key=None) -> str:
  """
  Generate and persist state for OAuth2 flow.
  
  Args:
      key (str, optional): Unique key for session state storage
      
  Returns:
      str: The generated state string
  """
  state_key = f"state-{key}"
  
  if not st.session_state.get(state_key):
    st.session_state[state_key] = uuid.uuid4().hex
  return st.session_state[state_key]


def _generate_pkce_pair(pkce: str, key=None) -> Tuple[str, str]:
  """
  Generate code_verifier and code_challenge for PKCE (Proof Key for Code Exchange).
  
  Args:
      pkce (str): The PKCE method to use (only S256 is supported)
      key (str, optional): Unique key for session state storage
      
  Returns:
      tuple: (code_verifier, code_challenge) pair for PKCE
      
  Raises:
      StreamlitOauthError: If unsupported PKCE method is provided
  """
  pkce_key = f"pkce-{key}"

  if pkce != "S256":
    raise StreamlitOauthError(f"Unsupported PKCE method: {pkce}. Only S256 is supported")
    
  if not st.session_state.get(pkce_key):
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = create_s256_code_challenge(code_verifier)
    st.session_state[pkce_key] = (code_verifier, code_challenge)
    
  return st.session_state[pkce_key]


class OAuth2Component:
  """
  Streamlit component for OAuth2 authorization.
  
  This component provides a streamlit interface for OAuth2 authorization code flow,
  including PKCE support and token management.
  """
  
  def __init__(
      self, 
      client_id: Optional[str] = None, 
      client_secret: Optional[str] = None, 
      authroize_endpoint: Optional[str] = None,  # Kept for backwards compatibility
      token_endpoint: Optional[str] = None, 
      refresh_token_endpoint: Optional[str] = None, 
      revoke_token_endpoint: Optional[str] = None, 
      client: Optional[Any] = None, 
      *, 
      authorize_endpoint: Optional[str] = None, 
      token_endpoint_auth_method: str = "client_secret_basic", 
      revocation_endpoint_auth_method: str = "client_secret_basic"
  ):
    """
    Initialize the OAuth2Component.
    
    Args:
        client_id: The OAuth2 client ID
        client_secret: The OAuth2 client secret
        authroize_endpoint: (deprecated, use authorize_endpoint) The authorize endpoint URL
        token_endpoint: The token endpoint URL
        refresh_token_endpoint: The refresh token endpoint URL
        revoke_token_endpoint: The revoke token endpoint URL
        client: An existing OAuth2 client (if provided, other params are ignored)
        authorize_endpoint: The authorize endpoint URL
        token_endpoint_auth_method: The auth method for token endpoint
        revocation_endpoint_auth_method: The auth method for revocation endpoint
    """
    # Handle typo in backwards-compatible way
    authorize_endpoint = authorize_endpoint or authroize_endpoint
    
    if client:
      self.client = client
      self.authorize_endpoint = None
      self.token_endpoint = None
      self.refresh_token_endpoint = None
      self.revoke_token_endpoint = None
    else:
      if not client_id or not authorize_endpoint or not token_endpoint:
        raise StreamlitOauthError("client_id, authorize_endpoint, and token_endpoint are required")
        
      self.client = AsyncOAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint_auth_method=token_endpoint_auth_method,
      )
      self.authorize_endpoint = authorize_endpoint
      self.token_endpoint = token_endpoint
      self.refresh_token_endpoint = refresh_token_endpoint or token_endpoint
      self.revoke_token_endpoint = revoke_token_endpoint
      self.token_endpoint_auth_method = token_endpoint_auth_method
      self.revocation_endpoint_auth_method = revocation_endpoint_auth_method

  def authorize_button(
      self, 
      name: str, 
      redirect_uri: str, 
      scope: str, 
      height: int = 800, 
      width: int = 600, 
      key: Optional[str] = None, 
      pkce: Optional[str] = None, 
      extra_params: Optional[Dict[str, Any]] = None, 
      icon: Optional[str] = None, 
      use_container_width: bool = False, 
      auto_click: bool = False
  ) -> Optional[Dict[str, Any]]:
    """
    Create an authorize button for OAuth2 authorization.
    
    Args:
        name: The button text
        redirect_uri: The redirect URI for the OAuth2 flow
        scope: Space-separated list of OAuth2 scopes
        height: Height of the popup window
        width: Width of the popup window
        key: Unique key for component state
        pkce: PKCE method (only S256 is supported)
        extra_params: Additional parameters to include in the authorization request
        icon: Icon URL or data URI to display on the button
        use_container_width: Whether the button should expand to container width
        auto_click: Whether to automatically click the button on load
        
    Returns:
        dict: OAuth2 result containing tokens or authorization errors
        
    Raises:
        StreamlitOauthError: If the OAuth2 flow fails or state mismatch occurs
    """
    if extra_params is None:
      extra_params = {}
    
    # Generate state based on key
    state = _generate_state(key)
    logger.debug(f"Generated state: {state}")
    
    # Set up authorization parameters
    auth_params = {
      "redirect_uri": redirect_uri,
      "scope": scope,
      "state": state,
      **extra_params
    }
    
    # Handle PKCE if requested
    if pkce:
      code_verifier, code_challenge = _generate_pkce_pair(pkce, key)
      # Authlib handles PKCE differently - we store code_verifier in client
      # and add code_challenge to params
      self.client.code_verifier = code_verifier
      auth_params["code_challenge"] = code_challenge
      auth_params["code_challenge_method"] = pkce

    try:
      # Create authorization URL - authlib returns this synchronously, not as coroutine
      auth_uri, _ = self.client.create_authorization_url(
        self.authorize_endpoint,
        **auth_params
      )
      logger.debug(f"Generated authorization URL for {redirect_uri}")
    except Exception as e:
      logger.error(f"Failed to generate authorization URL: {str(e)}")
      raise StreamlitOauthError(f"Failed to generate authorization URL: {str(e)}") from e

    # Present the authorize button to the user
    result = _authorize_button(
      authorization_url=auth_uri,
      name=name, 
      popup_height=height,
      popup_width=width,
      key=key,
      icon=icon,
      use_container_width=use_container_width,
      auto_click=auto_click,
    )

    # Process the authorization result
    if result:
      try:
        # Clean up session state
        del st.session_state[f'state-{key}']
        if pkce:
          del st.session_state[f'pkce-{key}']
      except KeyError as e:
        logger.warning(f"Failed to clean up session state: {str(e)}")
        # Continue processing even if cleanup fails
      
      # Handle errors from the OAuth provider
      if 'error' in result:
        error_msg = f"OAuth authorization error: {result.get('error')}, description: {result.get('error_description', 'No description')}"
        logger.error(error_msg)
        raise StreamlitOauthError(error_msg)
      
      # Verify state parameter to prevent CSRF attacks
      if 'state' in result and result['state'] != state:
        error_msg = f"State mismatch: expected {state}, got {result['state']}"
        logger.error(error_msg)
        raise StreamlitOauthError(error_msg)
      
      # Exchange authorization code for tokens
      if 'code' in result:
        try:
          # Exchange code for token using authlib (this is a real async method)
          # Set up token fetch parameters
          token_params = {
            "code": result['code'],
            "redirect_uri": redirect_uri,
          }
          
          # Pass code_verifier for PKCE
          if pkce and hasattr(self.client, 'code_verifier'):
            token_params['code_verifier'] = self.client.code_verifier
            logger.debug(f"Including code_verifier for PKCE token exchange")
          
          token = asyncio.run(
            self.client.fetch_token(
              self.token_endpoint,
              **token_params
            )
          )
          result['token'] = token
          logger.debug(f"Successfully obtained access token")
        except Exception as e:
          logger.error(f"Failed to exchange code for token: {str(e)}")
          raise StreamlitOauthError(f"Failed to exchange code for token: {str(e)}") from e
      
      # Handle ID token if present (for OpenID Connect)
      if 'id_token' in result.get('token', {}):
        try:
          # Parse ID token payload
          id_token = result['token']['id_token']
          # Basic JWT payload extraction (not secure without verification)
          payload = id_token.split('.')[1]
          payload += "=" * (-len(payload) % 4)  # Add padding if needed
          result['token']['id_token_payload'] = base64.b64decode(payload).decode('utf-8')
        except Exception as e:
          logger.warning(f"Failed to decode ID token: {str(e)}")

    return result
  
  def refresh_token(self, token: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
    """
    Refresh an OAuth2 access token if expired or if forced.
    
    Args:
        token (dict): The token dictionary containing access_token, refresh_token, etc.
        force (bool): Whether to force refresh even if the token is not expired
        
    Returns:
        dict: The refreshed token or the original token if not expired
        
    Raises:
        StreamlitOauthError: If refresh fails or no refresh token is available
    """
    # Check if token needs refreshing
    needs_refresh = force
    if not force and token.get('expires_at'):
      needs_refresh = token['expires_at'] < time.time()
      
    if needs_refresh:
      if not token.get('refresh_token'):
        raise StreamlitOauthError("Token is expired and no refresh token is available")
      
      try:
        # Create a new client for refresh to avoid state issues
        # Use the stored auth method
        client = AsyncOAuth2Client(
          token=token,
          client_id=self.client.client_id,
          client_secret=self.client.client_secret,
          token_endpoint_auth_method=self.token_endpoint_auth_method,
        )
        
        # Refresh the token (this is async)
        new_token = asyncio.run(
          client.refresh_token(
            self.refresh_token_endpoint
          )
        )
        logger.debug("Successfully refreshed access token")
        return new_token
      except Exception as e:
        logger.error(f"Failed to refresh token: {str(e)}")
        raise StreamlitOauthError(f"Failed to refresh token: {str(e)}") from e
    
    return token
  
  def revoke_token(self, token: Dict[str, Any], token_type_hint: str = "access_token") -> bool:
    """
    Revoke an OAuth2 token.
    
    Args:
        token (dict): The token dictionary containing access_token, refresh_token, etc.
        token_type_hint (str): Which token to revoke ('access_token' or 'refresh_token')
        
    Returns:
        bool: True if revocation was attempted (success not guaranteed)
        
    Note:
        Some OAuth providers ignore revocation errors, so this method does not raise
        exceptions on failure but logs them instead.
    """
    if not token or not self.revoke_token_endpoint:
      logger.warning("Cannot revoke token: missing token or revocation endpoint")
      return False
      
    try:
      # Extract the token value based on the type hint
      if token_type_hint == "access_token":
        token_value = token['access_token']
      elif token_type_hint == "refresh_token":
        token_value = token['refresh_token']
      else:
        logger.warning(f"Unsupported token_type_hint: {token_type_hint}")
        return False
      
      # Create a new client for revocation to avoid state issues
      # Use the stored auth method
      client = AsyncOAuth2Client(
        client_id=self.client.client_id,
        client_secret=self.client.client_secret,
        token_endpoint_auth_method=self.revocation_endpoint_auth_method,
      )
      
      # Set up revocation params
      revoke_params = {
        "token": token_value,
        "token_type_hint": token_type_hint
      }
      
      # Revoke the token (this is async)
      asyncio.run(
        client.revoke_token(
          self.revoke_token_endpoint,
          **revoke_params
        )
      )
      logger.debug(f"Successfully requested token revocation for {token_type_hint}")
      return True
    except KeyError as e:
      logger.warning(f"Token does not contain {token_type_hint}: {str(e)}")
      return False
    except Exception as e:
      # Many OAuth providers don't properly implement token revocation
      # or return errors even on successful revocation, so we log but don't raise
      logger.warning(f"Token revocation may have failed: {str(e)}")
      return False


# Demo code when running this file directly
if not _RELEASE:
    import streamlit as st
    from dotenv import load_dotenv
    
    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    logger.info("Running in development mode")
    
    # Load environment variables
    load_dotenv()
    AUTHORIZATION_URL = os.environ.get("AUTHORIZATION_URL")
    TOKEN_URL = os.environ.get("TOKEN_URL")
    REVOKE_URL = os.environ.get("REVOKE_URL")
    CLIENT_ID = os.environ.get("CLIENT_ID")
    CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
    REDIRECT_URI = os.environ.get("REDIRECT_URI", "http://localhost:3000")
    SCOPE = os.environ.get("SCOPE", "openid email profile")
    
    # Log configuration
    logger.info(f"Authorization URL: {AUTHORIZATION_URL}")
    logger.info(f"Token URL: {TOKEN_URL}")
    logger.info(f"Redirect URI: {REDIRECT_URI}")
    logger.info(f"Scope: {SCOPE}")
   
    # Create OAuth component
    oauth2 = OAuth2Component(
      CLIENT_ID, 
      CLIENT_SECRET, 
      AUTHORIZATION_URL, 
      TOKEN_URL, 
      TOKEN_URL, 
      REVOKE_URL
    )

    st.write("# OAuth2 Demo")
    st.write("This is a demo of the OAuth2 component for Streamlit using Authlib.")
    
    # Demo authorization flow
    if 'token' not in st.session_state:
      st.write("### Authorization")
      st.write("Click the button below to start the authorization flow:")
      
      # Save pkce for later use
      if 'pkce_verifier' not in st.session_state:
        st.session_state.pkce_verifier = secrets.token_urlsafe(64)
        logger.debug(f"Generated new PKCE verifier and stored in session state")
      
      extra_params = {
        "prompt": "consent", 
        "access_type": "offline"
      }
      
      # Create the authorize button
      result = oauth2.authorize_button(
        "Continue with OAuth Provider", 
        REDIRECT_URI, 
        SCOPE, 
        icon="data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' viewBox='0 0 48 48'%3E%3Cdefs%3E%3Cpath id='a' d='M44.5 20H24v8.5h11.8C34.7 33.9 30.1 37 24 37c-7.2 0-13-5.8-13-13s5.8-13 13-13c3.1 0 5.9 1.1 8.1 2.9l6.4-6.4C34.6 4.1 29.6 2 24 2 11.8 2 2 11.8 2 24s9.8 22 22 22c11 0 21-8 21-22 0-1.3-.2-2.7-.5-4z'/%3E%3C/defs%3E%3CclipPath id='b'%3E%3Cuse xlink:href='%23a' overflow='visible'/%3E%3C/clipPath%3E%3Cpath clip-path='url(%23b)' fill='%23FBBC05' d='M0 37V11l17 13z'/%3E%3Cpath clip-path='url(%23b)' fill='%23EA4335' d='M0 11l17 13 7-6.1L48 14V0H0z'/%3E%3Cpath clip-path='url(%23b)' fill='%2334A853' d='M0 37l30-23 7.9 1L48 0v48H0z'/%3E%3Cpath clip-path='url(%23b)' fill='%234285F4' d='M48 48L17 24l-4-3 35-10z'/%3E%3C/svg%3E", 
        use_container_width=True, 
        pkce="S256", 
        extra_params=extra_params,
        key="demo_oauth"
      )
      
      # Handle authorization result
      if result:
        logger.debug(f"Authorization result: {result}")
        if 'error' in result:
          st.error(f"Authentication error: {result.get('error')}")
        elif 'token' in result:
          token = result.get('token')
          st.session_state.token = token
          
          # Log token details for debugging
          logger.debug(f"Token received: {token.keys()}")
          if 'refresh_token' in token:
            logger.debug("Refresh token is present")
          else:
            logger.warning("No refresh token in response")
            
          st.success("Successfully authenticated!")
          st.rerun()
        else:
          st.warning("No token returned")
          st.json(result)
    else:
      # Display token and token management options
      st.write("### Authenticated")
      st.success("You are authenticated!")
      
      token = st.session_state['token']
      
      # Display token info
      with st.expander("Token Information"):
        st.json(token)
      
      col1, col2 = st.columns(2)
      
      # Refresh token button
      if col1.button("♻️ Refresh Token"):
        try:
          token = oauth2.refresh_token(token, force=True)
          st.session_state.token = token
          st.success("Token refreshed successfully!")
          st.rerun()
        except Exception as e:
          st.error(f"Error refreshing token: {str(e)}")
        
      # Revoke token button
      if col2.button("🗑 Revoke Token"):
        try:
          result = oauth2.revoke_token(token)
          if result:
            st.success("Token revoked successfully!")
          else:
            st.warning("Token revocation may have failed")
          del st.session_state.token
          if 'pkce_verifier' in st.session_state:
            del st.session_state.pkce_verifier
          st.rerun()
        except Exception as e:
          st.error(f"Error revoking token: {str(e)}")