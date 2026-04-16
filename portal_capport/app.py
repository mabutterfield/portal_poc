"""
CAPPORT (RFC 8908/8910) captive portal service.

Implements the Captive Portal API alongside a guest auth page and an admin
UI for manually exercising the FortiGate REST API during Phase 3 development.

Phases
------
Phase 1  GET /api/capport/status
         RFC 8908 status endpoint.  Queries FortiGate to determine whether
         the requesting client IP is already authenticated.
         Returns application/captive+json.

Phase 2  GET/POST /auth
         Guest auth page (teal theme, distinct from the 302 portal).
         Validates room + last name against mock PMS.
         On success: marks IP as pending in auth_state, shows result page.
         No FortiGate push yet — that is Phase 3.

Phase 3  POST /admin/fgt/auth   (manual via admin UI)
         Pushes a username + IP to FortiGate's firewall auth API.
         Admin selects the IP (from pending_auth or free-form) and username.

Phase 4  Baked into Phase 1: GET /user/firewall on FortiGate is called to
         determine captive: true/false — so once Phase 3 manually pushes an
         entry, the status endpoint automatically returns captive: false on
         the next OS poll.

Admin UI  GET /admin
          Live FortiGate user table, manual auth push, manual deauth,
          raw API response display, link to mock PMS admin.
"""

import os
import logging
import sys
import json
import requests as http
import urllib3
from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, make_response)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'capport-dev-key')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

MOCK_PMS_URL     = os.environ.get('MOCK_PMS_URL',     'http://mock_pms:5000')
PMS_TIMEOUT_SEC  = float(os.environ.get('PMS_TIMEOUT', '3'))
CAPPORT_SERVER_URL = os.environ.get('CAPPORT_SERVER_URL', 'https://localhost:8443')

FGT_HOST         = os.environ.get('FGT_HOST',         '10.255.112.50')
FGT_API_TOKEN    = os.environ.get('FGT_API_TOKEN',     '')
FGT_VDOM         = os.environ.get('FGT_VDOM',         'root')
FGT_VERIFY_TLS   = os.environ.get('FGT_VERIFY_TLS',   'false').lower() not in ('false', '0', 'no')

MOCK_PMS_ADMIN_URL = os.environ.get('MOCK_PMS_ADMIN_URL', 'http://localhost:5000/admin')

if not FGT_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# In-memory auth state
# Keyed by client IP.  Values: 'pending' (PMS verified, FGT push not done yet)
# Cleared when FGT confirms authentication (captive: false).
# Single worker required (see Dockerfile).
# ---------------------------------------------------------------------------
auth_state: dict = {}   # ip -> {'name', 'tier', 'room', 'username'}


# ---------------------------------------------------------------------------
# FortiGate API helpers
# ---------------------------------------------------------------------------

def _fgt_headers() -> dict:
    return {
        'Authorization': f'Bearer {FGT_API_TOKEN}',
        'Accept':        'application/json',
        'Content-Type':  'application/json',
    }


def fgt_get_users() -> tuple[list, str | None]:
    """
    GET /api/v2/monitor/user/firewall
    Returns (results_list, error_string).  error_string is None on success.
    """
    url = f'https://{FGT_HOST}/api/v2/monitor/user/firewall'
    try:
        resp = http.get(url, headers=_fgt_headers(), params={'vdom': FGT_VDOM},
                        timeout=5, verify=FGT_VERIFY_TLS)
        data = resp.json()
        if resp.status_code == 200 and data.get('status') == 'success':
            return data.get('results', []), None
        return [], f"FortiGate returned {resp.status_code}: {data.get('status')}"
    except Exception as exc:
        return [], str(exc)


def fgt_auth_user(username: str, ip: str) -> tuple[dict, str | None]:
    """
    POST /api/v2/monitor/user/firewall/auth
    Returns (response_dict, error_string).
    """
    url = f'https://{FGT_HOST}/api/v2/monitor/user/firewall/auth'
    payload = {'username': username, 'ip': ip}
    try:
        resp = http.post(url, headers=_fgt_headers(), params={'vdom': FGT_VDOM},
                         json=payload, timeout=5, verify=FGT_VERIFY_TLS)
        return resp.json(), None
    except Exception as exc:
        return {}, str(exc)


def fgt_deauth_user(user_id: int, ip: str) -> tuple[dict, str | None]:
    """
    POST /api/v2/monitor/user/firewall/deauth
    Returns (response_dict, error_string).
    """
    url = f'https://{FGT_HOST}/api/v2/monitor/user/firewall/deauth'
    payload = {
        'user_type': 'firewall',
        'method':    'firewall',
        'users':     [{'id': user_id, 'ip': ip}],
    }
    try:
        resp = http.post(url, headers=_fgt_headers(), params={'vdom': FGT_VDOM},
                         json=payload, timeout=5, verify=FGT_VERIFY_TLS)
        return resp.json(), None
    except Exception as exc:
        return {}, str(exc)


def fgt_ip_is_authed(client_ip: str) -> tuple[bool, int]:
    """
    Check whether client_ip appears in FortiGate's firewall auth table.
    Returns (is_authed, expiry_secs).
    """
    users, err = fgt_get_users()
    if err:
        logger.warning(f"FGT user list error during status check: {err}")
        return False, 0
    for u in users:
        if u.get('ipaddr') == client_ip:
            return True, u.get('expiry_secs', 0)
    return False, 0


# ---------------------------------------------------------------------------
# PMS lookup helper
# ---------------------------------------------------------------------------

def pms_lookup(room: str, last_name: str, ip: str) -> dict:
    payload = {
        'room':      room,
        'last_name': last_name,
        'ip':        ip,
        'source':    'capport',
    }
    try:
        resp = http.post(f'{MOCK_PMS_URL}/api/lookup',
                         json=payload, timeout=PMS_TIMEOUT_SEC)
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        logger.error(f"PMS unreachable: {exc}")
    return {'found': False}


# ---------------------------------------------------------------------------
# Phase 1 — CAPPORT status endpoint  (RFC 8908)
# ---------------------------------------------------------------------------

@app.route('/api/capport/status')
def capport_status():
    """
    RFC 8908 Captive Portal API status endpoint.

    The FortiGate DHCP server provides this URL via Option 160.
    The client OS queries it to determine network captive state.

    - captive: true  → OS opens user-portal-url in a system WebSheet
    - captive: false → OS closes WebSheet; client has internet access
    """
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Strip port if present
    if ':' in client_ip and '.' in client_ip:
        client_ip = client_ip.split(':')[0]

    is_authed, expiry = fgt_ip_is_authed(client_ip)

    if is_authed:
        logger.info(f"CAPPORT status: captive=false for {client_ip} (expiry={expiry}s)")
        body = {
            'captive':           False,
            'seconds-remaining': expiry,
        }
    else:
        logger.info(f"CAPPORT status: captive=true for {client_ip}")
        body = {
            'captive':          True,
            'user-portal-url':  f'{CAPPORT_SERVER_URL}/auth',
            'can-extend-session': False,
        }

    resp = make_response(jsonify(body))
    resp.headers['Content-Type'] = 'application/captive+json'
    resp.headers['Cache-Control'] = 'no-cache, no-store'
    return resp


# ---------------------------------------------------------------------------
# Phase 2 — Auth page
# ---------------------------------------------------------------------------

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'GET':
        return render_template('auth.html')

    # Form submission
    tier         = request.form.get('group', '')
    last_name    = request.form.get('username', '').strip()
    room         = request.form.get('room', '').strip()
    client_ip    = request.headers.get('X-Forwarded-For', request.remote_addr)

    VALID_TIERS = ('public', 'free', 'premium')
    if tier not in VALID_TIERS:
        return render_template('auth.html', error='Please select an access type.')

    # Public path — no PMS lookup needed
    if tier == 'public':
        logger.info(f"CAPPORT public auth from {client_ip}")
        auth_state[client_ip] = {
            'name':     'Guest',
            'tier':     'public',
            'room':     '',
            'username': 'local_public',
        }
        return render_template('result.html',
                               success=True,
                               name='Guest',
                               tier='public',
                               room='',
                               client_ip=client_ip,
                               phase3_pending=True)

    # Hotel guest path — validate fields
    if not last_name:
        return render_template('auth.html', error='Please enter your last name.')
    if not room:
        return render_template('auth.html', error='Please enter your room number.')

    result = pms_lookup(room=room, last_name=last_name, ip=client_ip)

    if result.get('found'):
        first_name = result.get('first_name', last_name)
        username   = 'local_premium' if tier == 'premium' else 'local_free'
        auth_state[client_ip] = {
            'name':     first_name,
            'tier':     tier,
            'room':     room,
            'username': username,
        }
        logger.info(
            f"CAPPORT PMS match — name={first_name!r}, room={room!r}, "
            f"tier={tier!r}, ip={client_ip}"
        )
        return render_template('result.html',
                               success=True,
                               name=first_name,
                               tier=tier,
                               room=room,
                               client_ip=client_ip,
                               phase3_pending=True)
    else:
        logger.warning(
            f"CAPPORT PMS no match — last_name={last_name!r}, room={room!r}, ip={client_ip}"
        )
        return render_template('result.html',
                               success=False,
                               name=last_name,
                               tier=tier,
                               room=room,
                               client_ip=client_ip,
                               phase3_pending=False)


# ---------------------------------------------------------------------------
# Admin UI  (Phase 3 testing + FortiGate API explorer)
# ---------------------------------------------------------------------------

@app.route('/admin')
def admin():
    users, fgt_error = fgt_get_users()
    pending = [
        {'ip': ip, **state}
        for ip, state in auth_state.items()
    ]
    return render_template('admin.html',
                           fgt_users=users,
                           fgt_error=fgt_error,
                           pending_auth=pending,
                           pms_admin_url=MOCK_PMS_ADMIN_URL,
                           api_response=None)


@app.route('/admin/fgt/auth', methods=['POST'])
def admin_fgt_auth():
    username  = request.form.get('username', '').strip()
    client_ip = request.form.get('ip', '').strip()

    resp_data, err = fgt_auth_user(username, client_ip)
    api_response = {
        'action':   f'POST /user/firewall/auth',
        'payload':  {'username': username, 'ip': client_ip},
        'response': resp_data,
        'error':    err,
    }
    logger.info(f"Admin FGT auth push: user={username!r}, ip={client_ip!r}, "
                f"result={resp_data.get('status')!r}, err={err!r}")

    users, fgt_error = fgt_get_users()
    pending = [{'ip': ip, **state} for ip, state in auth_state.items()]
    return render_template('admin.html',
                           fgt_users=users,
                           fgt_error=fgt_error,
                           pending_auth=pending,
                           pms_admin_url=MOCK_PMS_ADMIN_URL,
                           api_response=api_response)


@app.route('/admin/fgt/deauth', methods=['POST'])
def admin_fgt_deauth():
    user_id   = int(request.form.get('user_id', 0))
    client_ip = request.form.get('ip', '').strip()

    resp_data, err = fgt_deauth_user(user_id, client_ip)
    api_response = {
        'action':   'POST /user/firewall/deauth',
        'payload':  {'id': user_id, 'ip': client_ip},
        'response': resp_data,
        'error':    err,
    }
    logger.info(f"Admin FGT deauth: id={user_id}, ip={client_ip!r}, "
                f"result={resp_data.get('status')!r}, err={err!r}")

    # Remove from local pending state if present
    auth_state.pop(client_ip, None)

    users, fgt_error = fgt_get_users()
    pending = [{'ip': ip, **state} for ip, state in auth_state.items()]
    return render_template('admin.html',
                           fgt_users=users,
                           fgt_error=fgt_error,
                           pending_auth=pending,
                           pms_admin_url=MOCK_PMS_ADMIN_URL,
                           api_response=api_response)


@app.route('/admin/fgt/refresh')
def admin_fgt_refresh():
    return redirect(url_for('admin'))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=8443,
        ssl_context=(
            os.environ.get('TLS_CERT', '/certs/portal.crt'),
            os.environ.get('TLS_KEY',  '/certs/portal.key'),
        ),
        debug=False
    )
