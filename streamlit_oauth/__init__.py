import os
import streamlit.components.v1 as components
import asyncio
import random
import string
import streamlit as st
from httpx_oauth.oauth2 import OAuth2
import base64
import time

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

@st.cache_data(ttl=300)
def _generate_state():
  """
  persist state for 300 seconds (5 minutes) to keep component state hash the same
  """
  return ''.join(random.choice(string.digits) for x in range(10))

class OAuth2Component:
  def __init__(self, client_id, client_secret, authroize_endpoint, token_endpoint, refresh_token_endpoint, revoke_token_endpoint):
    self.client = OAuth2(
      client_id,
      client_secret,
      authroize_endpoint,
      token_endpoint,
      refresh_token_endpoint=refresh_token_endpoint,
      revoke_token_endpoint=revoke_token_endpoint,
    )

  def authorize_button(self, name, redirect_uri, scope, height=800, width=600, key=None):
    authorize_request = asyncio.run(self.client.get_authorization_url(
      redirect_uri=redirect_uri,
      scope=scope.split(" "),
      state=_generate_state(),
    ))

    # print(f'generated authorize request: {authorize_request}')

    result = _authorize_button(
      authorization_url=authorize_request,
      name=name, 
      popup_height=height,
      popup_width=width,
      key=key,
    )
    # print(f'result: {result}')

    if result:
      if 'error' in result:
        raise Exception(result)
      if result['state'] != _generate_state():
        raise Exception("STATE DOES NOT MATCH OR OUT OF DATE")
      if 'code' in result:
        result['token'] = asyncio.run(self.client.get_access_token(result['code'], redirect_uri))
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
  
  # FIXME: HTTPX_OAUTH DOES NOT IMPLEMENT REVOKE TOKEN (RFC7009) CORRECTLY, DISABLED FOR NOW 
  # def revoke_token(self, token, token_type_hint="access_token"):
  #   """
  #   Revokes the token
  #   """
  #   
  #   asyncio.run(self.client.revoke_token(token, token_type_hint))
  #   return True

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
      result = oauth2.authorize_button("🔗 Authorize", REDIRECT_URI, SCOPE)
      if result:
        
        st.session_state.token = result.get('token')
        st.experimental_rerun()
    else:
      token = st.session_state['token']
      st.json(token)
      if st.button("♻️ Refresh Token"):
        token = oauth2.refresh_token(token)
        st.session_state.token = token
        st.experimental_rerun()
    
