import os
import streamlit.components.v1 as components
import asyncio
import streamlit as st
from httpx_oauth.oauth2 import OAuth2
import base64
import time
import uuid
import hashlib
import base64
import secrets

_RELEASE = False
# comment out the following line to use the local dev server
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

@st.cache_data(ttl=300)
def _generate_state(key=None):
  """
  persist state for 300 seconds (5 minutes) to keep component state hash the same
  """
  return uuid.uuid4().hex

@st.cache_data(ttl=300)
def _generate_pkce_pair(pkce):
  """
  generate code_verifier and code_challenge for PKCE
  """
  if pkce != "S256":
    raise Exception("Only S256 is supported")
  code_verifier = secrets.token_urlsafe(100)
  code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().replace("=", "")
  return code_verifier, code_challenge

class OAuth2Component:
  def __init__(self, client_id=None, client_secret=None, authroize_endpoint=None, token_endpoint=None, refresh_token_endpoint=None, revoke_token_endpoint=None, client=None, *, authorize_endpoint=None):
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
      )

  def authorize_button(self, name, redirect_uri, scope, height=800, width=600, key=None, pkce=None, extras_params={}, icon=None, use_container_width=False):
    if pkce:
      code_verifier, code_challenge = _generate_pkce_pair(pkce)
      extras_params = {**extras_params, "code_challenge": code_challenge, "code_challenge_method": pkce}
    # generate state based on key
    state = _generate_state(key)
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
    )
    # print(f'result: {result}')

    if result:
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
        token = asyncio.run(self.client.refresh_token(token.get('refresh_token')))
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

if not _RELEASE:
    import streamlit as st
    from dotenv import load_dotenv
    load_dotenv()
    AUTHORIZATION_URL = os.environ.get("AUTHORIZATION_URL")
    TOKEN_URL = os.environ.get("TOKEN_URL")
    REVOKE_URL = os.environ.get("REVOKE_URL")
    CLIENT_ID = os.environ.get("CLIENT_ID")
    CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
    REDIRECT_URI = os.environ.get("REDIRECT_URI")
    SCOPE = os.environ.get("SCOPE")
   
    oauth2 = OAuth2Component(CLIENT_ID, CLIENT_SECRET, AUTHORIZATION_URL, TOKEN_URL, TOKEN_URL, REVOKE_URL)

    if 'token' not in st.session_state:
      result = oauth2.authorize_button("Continue with Google", REDIRECT_URI, SCOPE, icon="data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' viewBox='0 0 48 48'%3E%3Cdefs%3E%3Cpath id='a' d='M44.5 20H24v8.5h11.8C34.7 33.9 30.1 37 24 37c-7.2 0-13-5.8-13-13s5.8-13 13-13c3.1 0 5.9 1.1 8.1 2.9l6.4-6.4C34.6 4.1 29.6 2 24 2 11.8 2 2 11.8 2 24s9.8 22 22 22c11 0 21-8 21-22 0-1.3-.2-2.7-.5-4z'/%3E%3C/defs%3E%3CclipPath id='b'%3E%3Cuse xlink:href='%23a' overflow='visible'/%3E%3C/clipPath%3E%3Cpath clip-path='url(%23b)' fill='%23FBBC05' d='M0 37V11l17 13z'/%3E%3Cpath clip-path='url(%23b)' fill='%23EA4335' d='M0 11l17 13 7-6.1L48 14V0H0z'/%3E%3Cpath clip-path='url(%23b)' fill='%2334A853' d='M0 37l30-23 7.9 1L48 0v48H0z'/%3E%3Cpath clip-path='url(%23b)' fill='%234285F4' d='M48 48L17 24l-4-3 35-10z'/%3E%3C/svg%3E", use_container_width=True, pkce="S256", extras_params={"prompt": "consent", "access_type": "offline"})
      if result:
        
        st.session_state.token = result.get('token')
        st.rerun()
    else:
      token = st.session_state['token']
      st.json(token)
      if st.button("♻️ Refresh Token"):
        token = oauth2.refresh_token(token, force=True)
        st.session_state.token = token
        st.json(token)
        st.rerun()
      if st.button("🗑 Revoke Token"):
        oauth2.revoke_token(token)
        del st.session_state.token
        st.rerun()
    
