"""
CAPPORT (RFC 8908/8910) captive portal service.

Implements the Captive Portal API alongside a guest auth page and an admin
UI for monitoring sessions and manually retrying RSSO accounting pushes.

Phases
------
Phase 1  GET /api/capport/status
         RFC 8908 status endpoint.  Queries FortiGate to determine whether
         the requesting client IP is already authenticated.
         Returns application/captive+json.

Phase 2  GET/POST /auth
         Guest auth page (teal theme).
         Validates room + last name against mock PMS.
         On success: sends RSSO Accounting-Start to FortiGate immediately,
         stores session in auth_state, shows result page.

Phase 3  RSSO Accounting (automatic on /auth success, manual retry via admin)
         Sends a RADIUS Accounting-Start to FortiGate's RSSO listener.
         FortiGate maps Fortinet-Group-Name to the RSSO group and applies
         the matching firewall policy.  Accounting-Stop deauths the session.

Admin UI  GET /admin
          Live FortiGate user table, auth_state session list, manual RSSO
          retry push, RSSO deauth (Accounting-Stop), link to mock PMS admin.
"""

import os
import time
import socket
import struct
import hashlib
import random
import logging
import sys
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

MOCK_PMS_URL       = os.environ.get('MOCK_PMS_URL',       'http://mock_pms:5000')
PMS_TIMEOUT_SEC    = float(os.environ.get('PMS_TIMEOUT',  '3'))
CAPPORT_SERVER_URL = os.environ.get('CAPPORT_SERVER_URL', 'https://localhost:8443')
MOCK_PMS_ADMIN_URL = os.environ.get('MOCK_PMS_ADMIN_URL', 'http://localhost:5000/admin')

# FortiGate REST API (used for user table display and status checks)
FGT_HOST       = os.environ.get('FGT_HOST',       '10.255.112.50')
FGT_API_TOKEN  = os.environ.get('FGT_API_TOKEN',  '')
FGT_VDOM       = os.environ.get('FGT_VDOM',       'root')
FGT_VERIFY_TLS = os.environ.get('FGT_VERIFY_TLS', 'false').lower() not in ('false', '0', 'no')

# RSSO accounting — RADIUS Accounting-Start/Stop sent directly to FortiGate
# FGT_RSSO_IP: interface IP in the portal VDOM that accepts radius-acct traffic.
#              This is NOT the management IP (FGT_HOST) — accounting must be sent
#              to the local interface on the correct VDOM or FGT will drop it.
SHARED_SECRET  = os.environ.get('SHARED_SECRET', 'ch4ng3m3')
FGT_RSSO_PORT  = int(os.environ.get('FGT_RSSO_PORT', '1813'))
FGT_RSSO_IP    = os.environ.get('FGT_RSSO_IP',
                 os.environ.get('FORTIGATE_IP',
                 os.environ.get('FGT_HOST', '10.255.112.50')))
NAS_IP         = os.environ.get('NAS_IP', '127.0.0.1')

# Tier → RSSO group name (must match FortiGate RSSO group config)
RSSO_GROUP_MAP = {
    'public':  'rsso_public',
    'free':    'rsso_free',
    'premium': 'rsso_premium',
}

if not FGT_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# In-memory auth state
# Keyed by client IP.
# {name, last_name, tier, room, group, session_id, acct_sent, acct_error}
# Single worker required (see Dockerfile).
# ---------------------------------------------------------------------------
auth_state: dict = {}


# Local user → FGT group mapping for REST API push
LOCAL_USER_MAP = {
    'public':  'local_public',
    'free':    'local_free',
    'premium': 'local_premium',
}

# ---------------------------------------------------------------------------
# FortiGate REST API helpers
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
    Returns (results_list, error_string).
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
    Pushes a local FortiGate user into the firewall auth table by IP.
    The user must exist locally on FGT and be a member of a policy group.
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


def fgt_deauth_user(ip: str, user_id: int = 0) -> tuple[dict, str | None]:
    """
    POST /api/v2/monitor/user/firewall/deauth
    Deauths a locally-pushed user by IP.  user_id is static per local user
    definition and can be found via 'diagnose firewall auth list' on FGT.
    Returns (response_dict, error_string).
    """
    url = f'https://{FGT_HOST}/api/v2/monitor/user/firewall/deauth'
    payload = {
        'user_type':  'firewall',
        'method':     'firewall',
        'ip_version': 'ip4',
        'users':      [{'id': user_id, 'ip': ip, 'ip_version': 'ip4'}],
    }
    try:
        resp = http.post(url, headers=_fgt_headers(), params={'vdom': FGT_VDOM},
                         json=payload, timeout=5, verify=FGT_VERIFY_TLS)
        return resp.json(), None
    except Exception as exc:
        return {}, str(exc)


def fgt_ip_is_authed(client_ip: str) -> tuple[bool, int]:
    """
    Check whether client_ip appears in FortiGate's firewall/RSSO auth table.
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
# RSSO accounting — raw RADIUS UDP implementation
#
# Sends RADIUS Accounting-Request packets (RFC 2866) directly to FortiGate's
# RSSO listener on UDP port 1813.  No third-party RADIUS library required.
#
# Packet structure:
#   Code(1) | ID(1) | Length(2) | Authenticator(16) | Attributes
#
# Accounting authenticator = MD5(Code+ID+Length+16_zeros+Attributes+Secret)
#
# Fortinet-Group-Name is a VSA (vendor-specific attribute):
#   Attr 26 | Length | VendorID(4,BE) | Sub-type(1) | Sub-length(1) | Value
# ---------------------------------------------------------------------------

def _radius_attr(attr_type: int, value: bytes) -> bytes:
    """Encode a standard RADIUS attribute: Type(1) Length(1) Value."""
    return bytes([attr_type, 2 + len(value)]) + value


def _radius_vsa(vendor_id: int, sub_type: int, value: bytes) -> bytes:
    """Encode a Vendor-Specific attribute (RADIUS attr 26)."""
    sub_len = 2 + len(value)
    vsa_value = struct.pack('!IB', vendor_id, sub_type) + bytes([sub_len]) + value
    return _radius_attr(26, vsa_value)


def _build_acct_packet(status_type: int, attrs: bytes) -> bytes:
    """
    Build a RADIUS Accounting-Request packet.
    status_type: 1=Start, 2=Stop
    attrs: pre-encoded attribute bytes (everything except Acct-Status-Type)
    """
    code       = 4                      # Accounting-Request
    identifier = random.randint(0, 255)
    secret     = SHARED_SECRET.encode()

    # Acct-Status-Type attr (always first)
    acct_type_attr = _radius_attr(40, struct.pack('!I', status_type))
    all_attrs      = acct_type_attr + attrs

    length        = 20 + len(all_attrs)
    header        = bytes([code, identifier]) + struct.pack('!H', length)
    authenticator = hashlib.md5(header + b'\x00' * 16 + all_attrs + secret).digest()

    return header + authenticator + all_attrs


def _send_radius_acct(packet: bytes) -> tuple[bool, str | None]:
    """Send packet to FGT RSSO listener; wait briefly for Accounting-Response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(packet, (FGT_RSSO_IP, FGT_RSSO_PORT))
        try:
            sock.recv(1024)   # Accounting-Response (code 5) if FGT responds
        except socket.timeout:
            pass              # FGT may not respond until RSSO is configured;
                              # the packet was still sent and received
        sock.close()
        return True, None
    except Exception as exc:
        return False, str(exc)


def send_rsso_start(ip: str, username: str, group: str,
                    session_id: str) -> tuple[bool, str | None]:
    """
    Send RADIUS Accounting-Start to FortiGate RSSO listener.

    FortiGate RSSO uses the Class attribute (attr 25) for group matching:
      config user rsso → set sso-attribute Class
    The Class value must match sso-attribute-value in the RSSO user group.

    User-Name carries the guest's name for audit/display in the FGT auth table.
    """
    attrs = (
        _radius_attr(1,  username.encode())        +  # User-Name  (display / audit)
        _radius_attr(25, group.encode())           +  # Class      (RSSO group lookup)
        _radius_attr(8,  socket.inet_aton(ip))     +  # Framed-IP-Address
        _radius_attr(44, session_id.encode())      +  # Acct-Session-Id
        _radius_attr(4,  socket.inet_aton(NAS_IP))    # NAS-IP-Address
    )
    packet = _build_acct_packet(1, attrs)   # 1 = Start
    ok, err = _send_radius_acct(packet)
    if ok:
        logger.info(f"RSSO Start sent: ip={ip!r} user={username!r} "
                    f"group={group!r} session={session_id!r}")
    else:
        logger.error(f"RSSO Start failed: ip={ip!r} err={err}")
    return ok, err


def send_rsso_stop(ip: str, username: str, session_id: str,
                   group: str = '') -> tuple[bool, str | None]:
    """
    Send RADIUS Accounting-Stop to remove the RSSO session for this IP.
    Must mirror the Start packet: same User-Name (rsso-endpoint-attribute),
    same Class (sso-attribute), same Acct-Session-Id.
    """
    attrs = (
        _radius_attr(1,  username.encode())        +  # User-Name  (endpoint lookup)
        _radius_attr(25, group.encode())           +  # Class      (profile/group)
        _radius_attr(8,  socket.inet_aton(ip))     +  # Framed-IP-Address
        _radius_attr(44, session_id.encode())      +  # Acct-Session-Id
        _radius_attr(4,  socket.inet_aton(NAS_IP))    # NAS-IP-Address
    )
    packet = _build_acct_packet(2, attrs)   # 2 = Stop
    ok, err = _send_radius_acct(packet)
    if ok:
        logger.info(f"RSSO Stop sent: ip={ip!r} user={username!r} "
                    f"session={session_id!r}")
    else:
        logger.error(f"RSSO Stop failed: ip={ip!r} err={err}")
    return ok, err


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
            'captive':            True,
            'user-portal-url':    f'{CAPPORT_SERVER_URL}/auth',
            'can-extend-session': False,
        }

    resp = make_response(jsonify(body))
    resp.headers['Content-Type'] = 'application/captive+json'
    resp.headers['Cache-Control'] = 'no-cache, no-store'
    return resp


# ---------------------------------------------------------------------------
# Phase 2+3 — Auth page  (PMS validation + immediate RSSO accounting)
# ---------------------------------------------------------------------------

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'GET':
        return render_template('auth.html')

    tier      = request.form.get('group', '')
    last_name = request.form.get('username', '').strip()
    room      = request.form.get('room', '').strip()
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    VALID_TIERS = ('public', 'free', 'premium')
    if tier not in VALID_TIERS:
        return render_template('auth.html', error='Please select an access type.')

    group      = RSSO_GROUP_MAP[tier]
    session_id = f'capport-{client_ip}-{int(time.time())}'

    # Public path — no PMS lookup needed
    if tier == 'public':
        logger.info(f"CAPPORT public auth from {client_ip}")
        ok, err = send_rsso_start(client_ip, 'public_guest', group, session_id)
        auth_state[client_ip] = {
            'name':       'Guest',
            'last_name':  'public_guest',
            'tier':       'public',
            'room':       '',
            'group':      group,
            'session_id': session_id,
            'acct_sent':  ok,
            'acct_error': err,
        }
        return render_template('result.html',
                               success=True,
                               name='Guest',
                               tier='public',
                               room='',
                               client_ip=client_ip,
                               acct_sent=ok,
                               acct_error=err)

    # Hotel guest path — validate fields
    if not last_name:
        return render_template('auth.html', error='Please enter your last name.')
    if not room:
        return render_template('auth.html', error='Please enter your room number.')

    result = pms_lookup(room=room, last_name=last_name, ip=client_ip)

    if result.get('found'):
        first_name = result.get('first_name', last_name)
        ok, err = send_rsso_start(client_ip, last_name, group, session_id)
        auth_state[client_ip] = {
            'name':       first_name,
            'last_name':  last_name,
            'tier':       tier,
            'room':       room,
            'group':      group,
            'session_id': session_id,
            'acct_sent':  ok,
            'acct_error': err,
        }
        logger.info(
            f"CAPPORT PMS match — name={first_name!r}, room={room!r}, "
            f"tier={tier!r}, group={group!r}, ip={client_ip}, acct_ok={ok}"
        )
        return render_template('result.html',
                               success=True,
                               name=first_name,
                               tier=tier,
                               room=room,
                               client_ip=client_ip,
                               acct_sent=ok,
                               acct_error=err)
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
                               acct_sent=False,
                               acct_error=None)


# ---------------------------------------------------------------------------
# Admin UI
# ---------------------------------------------------------------------------

@app.route('/admin')
def admin():
    users, fgt_error = fgt_get_users()
    sessions = [{'ip': ip, **state} for ip, state in auth_state.items()]
    return render_template('admin.html',
                           fgt_users=users,
                           fgt_error=fgt_error,
                           pending_auth=sessions,
                           pms_admin_url=MOCK_PMS_ADMIN_URL,
                           api_response=None)


@app.route('/admin/fgt/auth', methods=['POST'])
def admin_fgt_auth():
    """
    Manual RSSO push — sends Accounting-Start with the supplied fields.
    Fields come directly from the form; auth_state is updated if an entry
    exists for this IP but the form values always take precedence.
    """
    client_ip  = request.form.get('ip',       '').strip()
    username   = request.form.get('username', '').strip() or 'unknown'
    group      = request.form.get('group',    'rsso_free').strip()
    # Reuse existing session_id if we have one; otherwise generate a new one
    state      = auth_state.get(client_ip, {})
    session_id = state.get('session_id', f'capport-{client_ip}-{int(time.time())}')

    ok, err = send_rsso_start(client_ip, username, group, session_id)

    # Always persist push details so deauth has the correct username,
    # group, and session_id — even for IPs not in auth_state from /auth flow.
    auth_state[client_ip] = {
        **auth_state.get(client_ip, {}),
        'last_name':  username,
        'group':      group,
        'session_id': session_id,
        'acct_sent':  ok,
        'acct_error': err,
    }

    api_response = {
        'action':   'RSSO Accounting-Start',
        'payload':  {
            'ip':         client_ip,
            'username':   username,
            'group':      group,
            'session_id': session_id,
        },
        'response': {'status': 'success' if ok else 'error'},
        'error':    err,
    }
    logger.info(f"Admin RSSO push: ip={client_ip!r} user={username!r} "
                f"group={group!r} ok={ok} err={err!r}")

    users, fgt_error = fgt_get_users()
    sessions = [{'ip': ip, **s} for ip, s in auth_state.items()]
    return render_template('admin.html',
                           fgt_users=users,
                           fgt_error=fgt_error,
                           pending_auth=sessions,
                           pms_admin_url=MOCK_PMS_ADMIN_URL,
                           api_response=api_response)


@app.route('/admin/fgt/local-auth', methods=['POST'])
def admin_fgt_local_auth():
    """
    Push a local FGT user into the firewall auth table via REST API.
    Uses the static local_public / local_free / local_premium accounts.
    The user_id is static per local user definition on FGT — look it up once
    via 'diagnose firewall auth list' after the first successful push.
    """
    client_ip = request.form.get('ip', '').strip()
    username  = request.form.get('username', '').strip()

    resp_data, err = fgt_auth_user(username, client_ip)
    api_response = {
        'action':   'FGT Local Auth (POST /user/firewall/auth)',
        'payload':  {'username': username, 'ip': client_ip},
        'response': resp_data,
        'error':    err,
    }
    logger.info(f"Admin local auth push: user={username!r} ip={client_ip!r} "
                f"status={resp_data.get('status')!r} err={err!r}")

    users, fgt_error = fgt_get_users()
    sessions = [{'ip': ip, **s} for ip, s in auth_state.items()]
    return render_template('admin.html',
                           fgt_users=users,
                           fgt_error=fgt_error,
                           pending_auth=sessions,
                           pms_admin_url=MOCK_PMS_ADMIN_URL,
                           api_response=api_response)


@app.route('/admin/fgt/deauth', methods=['POST'])
def admin_fgt_deauth():
    """
    Deauth a session.  Supports two methods selected by the 'method' form field:
      rsso  — sends RADIUS Accounting-Stop (default, for RSSO sessions)
      local — calls FGT REST API deauth (for locally-pushed users)
    """
    client_ip   = request.form.get('ip', '').strip()
    method      = request.form.get('method', 'rsso')
    state       = auth_state.get(client_ip, {})

    if method == 'local':
        # user_id is static per local user on FGT; stored in auth_state if known
        user_id = int(state.get('fgt_user_id', 0))
        resp_data, err = fgt_deauth_user(client_ip, user_id)
        action  = 'FGT Local Deauth (POST /user/firewall/deauth)'
        payload = {'ip': client_ip, 'user_id': user_id}
        ok      = err is None
        logger.info(f"Admin local deauth: ip={client_ip!r} user_id={user_id} "
                    f"status={resp_data.get('status')!r} err={err!r}")
        api_response = {
            'action':   action,
            'payload':  payload,
            'response': resp_data,
            'error':    err,
        }
    else:
        # RSSO — send Accounting-Stop
        username   = state.get('last_name', 'unknown')
        group      = state.get('group', '')
        session_id = state.get('session_id', f'capport-{client_ip}-manual')
        ok, err    = send_rsso_stop(client_ip, username, session_id, group)
        logger.info(f"Admin RSSO deauth: ip={client_ip!r} ok={ok} err={err!r}")
        api_response = {
            'action':   'RSSO Accounting-Stop',
            'payload':  {'ip': client_ip, 'username': username, 'session_id': session_id},
            'response': {'status': 'success' if ok else 'error'},
            'error':    err,
        }

    auth_state.pop(client_ip, None)

    users, fgt_error = fgt_get_users()
    sessions = [{'ip': ip, **s} for ip, s in auth_state.items()]
    return render_template('admin.html',
                           fgt_users=users,
                           fgt_error=fgt_error,
                           pending_auth=sessions,
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
