# CLAUDE.md

## Project Overview

**streamlit-oauth** is a Streamlit custom component that provides OAuth2 authorization code flow for Streamlit apps. It wraps [httpx-oauth](https://frankie567.github.io/httpx-oauth/) to handle the OAuth2 handshake via a popup window, returning tokens directly to the Streamlit session.

- **Package name**: `streamlit-oauth` (PyPI)
- **Current version**: 0.1.14 (in `setup.py`)
- **Python**: >= 3.9
- **License**: MIT

## Repository Structure

```
streamlit-oauth/
├── streamlit_oauth/
│   ├── __init__.py              # Main Python module (OAuth2Component, helpers)
│   └── frontend/                # Vite-based JS frontend component
│       ├── main.js              # Button + popup OAuth flow logic
│       ├── style.css            # Button styling (uses Streamlit CSS vars)
│       ├── index.html           # Entry point for the component
│       ├── vite.config.js       # Vite dev server on port 3000, relative base
│       ├── package.json         # JS deps: streamlit-component-lib, toastify-js
│       └── package-lock.json
├── examples/                    # Provider-specific usage examples
│   ├── google.py                # Google OIDC with PKCE
│   ├── github.py                # GitHub OAuth using httpx-oauth client
│   ├── discord.py               # Discord OAuth
│   ├── bitbucket.py             # Bitbucket OAuth
│   ├── notion.py                # Notion OAuth
│   ├── jira.py                  # Jira/Atlassian OAuth
│   ├── kinde.py                 # Kinde OIDC with PKCE
│   └── yandex.py                # Yandex OAuth
├── tests/
│   ├── test_internal.py         # Unit tests for _generate_state, _generate_pkce_pair
│   └── test_oauth_component.py  # Tests for OAuth2Component (authorize, refresh, revoke)
├── setup.py                     # Package metadata and dependencies
├── MANIFEST.in                  # Includes frontend/dist in sdist
├── .github/
│   ├── workflows/
│   │   ├── tests.yml            # CI: runs pytest on push/PR
│   │   └── pypi-publish.yml     # CD: builds + publishes to PyPI on v* tags
│   └── FUNDING.yml
├── .devcontainer/
│   └── devcontainer.json        # Codespaces config (Python 3.11, runs google example)
└── .gitignore
```

## Key Architecture

### Python (`streamlit_oauth/__init__.py`)

- **`OAuth2Component`**: Main class wrapping an `httpx_oauth.oauth2.OAuth2` client. Accepts either raw endpoint URLs or a pre-configured `httpx_oauth` client via the `client=` parameter.
  - `authorize_button()` - Generates the authorization URL, renders a Streamlit component button, handles the callback (code exchange, PKCE, state validation).
  - `refresh_token()` - Refreshes expired tokens; preserves old refresh token if not returned.
  - `revoke_token()` - Revokes access or refresh tokens.
- **`_generate_state(key)`** - Creates and caches a UUID state parameter in `st.session_state`.
- **`_generate_pkce_pair(pkce, key)`** - Generates S256 PKCE code_verifier/code_challenge pair, cached in session state.
- **`StreamlitOauthError`** - Custom exception for OAuth errors and state mismatches.
- The `_RELEASE` flag toggles between local dev server (port 3000) and built frontend (`frontend/dist`).

### Frontend (`streamlit_oauth/frontend/`)

- Vanilla JS (no framework) using `streamlit-component-lib`.
- Renders a styled button that opens an OAuth popup window.
- Polls the popup URL until it redirects to `redirect_uri`, then extracts query params and sends them back to Streamlit via `Streamlit.setComponentValue()`.
- Built with Vite; dev server runs on port 3000.

## Development Setup

### Prerequisites

- Python >= 3.9
- Node.js (for frontend development)

### Install Python dependencies

```bash
pip install -e .
pip install pytest
```

### Frontend development

```bash
cd streamlit_oauth/frontend
npm install
npm run dev        # Starts Vite dev server on port 3000
```

To develop locally, set `_RELEASE = False` in `__init__.py` (it's the first assignment; comment out the second `_RELEASE = True` line). Then run:

```bash
streamlit run streamlit_oauth/__init__.py --server.enableCORS=false
```

Create a `.env` file with OAuth credentials (`AUTHORIZATION_URL`, `TOKEN_URL`, `REVOKE_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `REDIRECT_URI`, `SCOPE`).

### Build frontend for release

```bash
cd streamlit_oauth/frontend
npm run build      # Outputs to frontend/dist/
```

## Testing

```bash
pytest
```

Tests use `monkeypatch` and `AsyncMock` to mock the httpx-oauth client and the Streamlit component. No real OAuth server is needed.

- `tests/test_internal.py` - Tests for state generation and PKCE pair generation helpers.
- `tests/test_oauth_component.py` - Tests for `authorize_button` (success + state mismatch), `refresh_token`, and `revoke_token`.

## CI/CD

- **CI** (`.github/workflows/tests.yml`): Runs `pytest` on pushes to `main`/`master` and all PRs.
- **CD** (`.github/workflows/pypi-publish.yml`): On `v*` tags, runs tests then builds and publishes to PyPI using `PYPI_API_TOKEN` secret.

## Code Conventions

- **Style**: 2-space indentation in Python (project convention, not PEP 8's 4 spaces). No type annotations on most functions.
- **Async pattern**: OAuth client methods are async (`httpx_oauth`) but called synchronously via `asyncio.run()` since Streamlit doesn't support async components natively.
- **Session state keys**: Prefixed with purpose — `state-{key}` for OAuth state, `pkce-{key}` for PKCE pairs.
- **Error handling**: Bare `except: pass` is used in some places (token revocation, session state cleanup). This is intentional — revocation failures and missing session keys are non-critical.
- **Backwards compatibility**: The `authroize_endpoint` typo parameter is preserved alongside the correct `authorize_endpoint` keyword argument.
- **Frontend**: Vanilla JS, no build framework. Uses Streamlit CSS variables (`--primary-color`, `--text-color`, `--background-color`) for theming.

## Dependencies

### Python (runtime)

- `streamlit >= 1.28.1`
- `httpx-oauth == 0.15.1` (pinned)
- `python-dotenv == 1.0.1` (pinned)

### Frontend

- `streamlit-component-lib ^1.4.0`
- `toastify-js ^1.12.0`
- `vite ^6.2.7` (dev)

## Common Tasks

| Task | Command |
|------|---------|
| Install for development | `pip install -e .` |
| Run tests | `pytest` |
| Run an example | `streamlit run examples/google.py` |
| Build frontend | `cd streamlit_oauth/frontend && npm run build` |
| Start frontend dev server | `cd streamlit_oauth/frontend && npm run dev` |

## Notes for AI Assistants

- The single Python source file (`streamlit_oauth/__init__.py`) contains all library code plus a dev-mode Streamlit app at the bottom (guarded by `if not _RELEASE`).
- When modifying OAuth logic, ensure state validation and PKCE flows remain intact — these are security-critical.
- The `_RELEASE = True` line must stay uncommented for production builds; only toggle it for local frontend development.
- Examples in `examples/` show two patterns: (1) raw endpoint URLs and (2) pre-built `httpx_oauth` client objects. Both should continue to work.
- Tests mock at the `asyncio.run` boundary — the `httpx_oauth` client methods are replaced with `AsyncMock`.
