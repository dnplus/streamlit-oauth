import os
import streamlit.components.v1 as components
import asyncio
import streamlit as st
from httpx_oauth.oauth2 import OAuth2, OAuth2ClientAuthMethod
import base64
import time
import uuid
import hashlib
import base64
import secrets

# set _RELEASE = False to use the local dev server
# use streamlit run __init__.py --server.enableCORS=false to run the local dev server
_RELEASE = True

if not _RELEASE:
  _authorize_button = components.declare_component(
    "authorize_button",
    url="http://localhost:3000", # vite dev server port
  )
else:
  parent_dir = os.path.dirname(os.path.abspath(__file__))
  build_dir = os.path.join(parent_dir, "frontend/dist")
  _authorize_button = components.declare_component("authorize_button", path=build_dir)


class StreamlitOauthError(Exception):
  """
  Exception raised from streamlit-oauth.
  """

def _generate_state(key=None):
  """
  persist state for 300 seconds (5 minutes) to keep component state hash the same
  """
  state_key = f"state-{key}"
  
  if not st.session_state.get(state_key):
    st.session_state[state_key] = uuid.uuid4().hex
  return st.session_state[state_key]

def _generate_pkce_pair(pkce, key=None):
  """
  generate code_verifier and code_challenge for PKCE
  """
  pkce_key = f"pkce-{key}"

  if pkce != "S256":
    raise Exception("Only S256 is supported")
  if not st.session_state.get(pkce_key):
    code_verifier = secrets.token_urlsafe(96)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().replace("=", "")
    st.session_state[pkce_key] = (code_verifier, code_challenge)
  return st.session_state[pkce_key]

class OAuth2Component:
  def __init__(self, client_id=None, client_secret=None, authroize_endpoint=None, token_endpoint=None, refresh_token_endpoint=None, revoke_token_endpoint=None, client=None, *, authorize_endpoint=None, token_endpoint_auth_method: OAuth2ClientAuthMethod = "client_secret_basic", revocation_endpoint_auth_method: OAuth2ClientAuthMethod = "client_secret_basic"):
    # Handle typo in backwards-compatible way
    authorize_endpoint = authorize_endpoint or authroize_endpoint
    if client:
      self.client = client
    else:
      self.client = OAuth2(
        client_id,
        client_secret,
        authorize_endpoint,
        token_endpoint,
        refresh_token_endpoint=refresh_token_endpoint,
        revoke_token_endpoint=revoke_token_endpoint,
        token_endpoint_auth_method=token_endpoint_auth_method,
        revocation_endpoint_auth_method=revocation_endpoint_auth_method,
      )

  def authorize_button(self, name, redirect_uri, scope, height=800, width=600, key=None, pkce=None, extras_params={}, icon=None, use_container_width=False, auto_click=False):
    # generate state based on key
    state = _generate_state(key)
    if pkce:
      code_verifier, code_challenge = _generate_pkce_pair(pkce, key)
      extras_params = {**extras_params, "code_challenge": code_challenge, "code_challenge_method": pkce}

    authorize_request = asyncio.run(self.client.get_authorization_url(
      redirect_uri=redirect_uri,
      scope=scope.split(" "),
      state=state,
      extras_params=extras_params
    ))

    # print(f'generated authorize request: {authorize_request}')

    result = _authorize_button(
      authorization_url=authorize_request,
      name=name, 
      popup_height=height,
      popup_width=width,
      key=key,
      icon=icon,
      use_container_width=use_container_width,
      auto_click=auto_click,
    )
    # print(f'result: {result}')

    if result:
      try:
        del st.session_state[f'state-{key}']
        del st.session_state[f'pkce-{key}'] 
      except:
        pass
      if 'error' in result:
        raise StreamlitOauthError(result)
      if 'state' in result and result['state'] != state:
        raise StreamlitOauthError(f"STATE {state} DOES NOT MATCH OR OUT OF DATE")
      if 'code' in result:
        args = {
          'code': result['code'],
          'redirect_uri': redirect_uri,
        }
        if pkce:
          args['code_verifier'] = code_verifier
        
        result['token'] = asyncio.run(self.client.get_access_token(**args))
      if 'id_token' in result:
        # TODO: verify id_token
        result['id_token'] = base64.b64decode(result['id_token'].split('.')[1] + '==')

    return result
  
  def refresh_token(self, token, force=False):
    """
    Returns a refreshed token if the token is expired, otherwise returns the same token
    """
    if force or token.get('expires_at') and token['expires_at'] < time.time():
      if token.get('refresh_token') is None:
        raise Exception("Token is expired and no refresh token is available")
      else:
        new_token = asyncio.run(self.client.refresh_token(token.get('refresh_token')))
        # Keep the old refresh token if the new one is missing it
        if not new_token.get('refresh_token'):
          new_token['refresh_token'] = token.get('refresh_token')
        token = new_token
    return token
  
  def revoke_token(self, token, token_type_hint="access_token"):
    """
    Revokes the token
    """
    if token_type_hint == "access_token":
      token = token['access_token']
    elif token_type_hint == "refresh_token":
      token = token['refresh_token']
    try:
      asyncio.run(self.client.revoke_token(token, token_type_hint))
    except:
      # discard exception if revoke fails
      pass
    return True

    
