import os
import logging
import requests as http
from flask import Flask, request, session, render_template

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-key-change-in-production')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

SHARED_SECRET   = os.environ.get('SHARED_SECRET',   'ch4ng3m3')
MOCK_PMS_URL    = os.environ.get('MOCK_PMS_URL',    'http://mock_pms:5000')
PMS_TIMEOUT_SEC = float(os.environ.get('PMS_TIMEOUT', '3'))

# Maps the user's tier selection to the RADIUS service account.
# FreeRADIUS returns Fortinet-Group-Name + Session-Timeout per account:
#   svc_public  → public_guests,  2 h
#   svc_free    → free_guests,    4 h
#   svc_premium → premium_guests, 16 h
GROUP_MAP = {
    'public':  'svc_public',
    'free':    'svc_free',
    'premium': 'svc_premium',
}


def pms_lookup(room: str, last_name: str, mac: str, ip: str, nas_ip: str) -> dict:
    """
    Call the mock PMS lookup API.

    Returns the full response dict on success, or a synthetic not-found dict
    if the lookup fails (PMS unreachable, timeout, non-200, etc.).
    All errors are logged but never bubble up to the caller — the portal
    always falls back to public on any failure.
    """
    payload = {
        'room':      room,
        'last_name': last_name,
        'mac':       mac,
        'ip':        ip,
        'nas_ip':    nas_ip,
    }
    try:
        resp = http.post(
            f'{MOCK_PMS_URL}/api/lookup',
            json=payload,
            timeout=PMS_TIMEOUT_SEC,
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning(
            f"PMS returned {resp.status_code} for room={room!r} last_name={last_name!r}"
        )
    except http.exceptions.Timeout:
        logger.error(f"PMS lookup timed out (>{PMS_TIMEOUT_SEC}s) for room={room!r}")
    except http.exceptions.RequestException as exc:
        logger.error(f"PMS unreachable: {exc}")

    return {'found': False}


@app.route('/auth')
def auth():
    """
    Entry point — FortiGate redirects unauthenticated clients here.

    Expected query parameters from FortiGate:
      post      URL to POST credentials back to (FortiGate fgtauth endpoint)
      magic     Opaque session token — must be echoed back verbatim
      usermac   Client MAC address
      userip    Client IP address
      ssid      SSID name
      apname    AP name
    """
    magic    = request.args.get('magic', '')
    post_url = request.args.get('post', '')
    usermac  = request.args.get('usermac', '')
    userip   = request.args.get('userip', '')
    ssid     = request.args.get('ssid', '')
    apname   = request.args.get('apname', '')

    if not magic or not post_url:
        logger.warning(
            f"Auth request missing required params — "
            f"magic={bool(magic)}, post={bool(post_url)}, "
            f"from {request.remote_addr}"
        )
        return render_template(
            'error.html',
            message='Invalid portal request. Please disconnect and reconnect to the network.'
        )

    session.clear()
    session['magic']    = magic
    session['post_url'] = post_url
    session['usermac']  = usermac
    session['userip']   = userip
    session['ssid']     = ssid
    session['apname']   = apname

    logger.info(
        f"Portal session started — "
        f"mac={usermac}, ip={userip}, ssid={ssid!r}, ap={apname}"
    )

    return render_template('login.html', ssid=ssid)


@app.route('/login', methods=['POST'])
def login():
    """
    Handles the guest form submission.

    - Public:          skip PMS, auth directly as svc_public.
    - Free / Premium:  call PMS to validate room + last name.
                       On match  → auth as the selected tier.
                       On failure → fall back to svc_public, flag in submit page.
    """
    tier         = request.form.get('group', '')
    display_name = request.form.get('username', '').strip()
    room         = request.form.get('room', '').strip()

    ssid   = session.get('ssid', '')
    magic  = session.get('magic')
    post_url = session.get('post_url')

    if not magic or not post_url:
        logger.warning(f"Session expired — tier={tier!r}, name={display_name!r}")
        return render_template(
            'error.html',
            message='Your session has expired. Please reconnect to the network and try again.'
        )

    if tier not in GROUP_MAP:
        return render_template('login.html', ssid=ssid, error='Please select an access type.')

    # Public path — no PMS lookup needed
    if tier == 'public':
        logger.info(
            f"Public auth — mac={session.get('usermac')}, ip={session.get('userip')}"
        )
        return render_template(
            'submit.html',
            post_url=post_url,
            magic=magic,
            username='svc_public',
            password=SHARED_SECRET,
            display_name='Guest',
            group='public',
            fallback=False,
        )

    # Guest / Premium path — validate form fields
    if not display_name:
        return render_template('login.html', ssid=ssid, error='Please enter your last name.')
    if not room:
        return render_template('login.html', ssid=ssid, error='Please enter your room number.')

    # PMS lookup
    result = pms_lookup(
        room=room,
        last_name=display_name,
        mac=session.get('usermac', ''),
        ip=session.get('userip', ''),
        nas_ip=request.remote_addr,
    )

    if result.get('found'):
        # Match — use the tier the guest selected (trust user selection for POC)
        radius_user  = GROUP_MAP[tier]
        friendly_name = result.get('first_name', display_name)
        fallback = False
        logger.info(
            f"PMS match — name={friendly_name!r}, room={room!r}, "
            f"tier={tier!r}, radius_user={radius_user}, "
            f"mac={session.get('usermac')}, ip={session.get('userip')}"
        )
    else:
        # No match — fall back to public
        radius_user   = 'svc_public'
        friendly_name = display_name
        fallback      = True
        tier          = 'public'
        logger.warning(
            f"PMS no match — name={display_name!r}, room={room!r}, "
            f"falling back to public, "
            f"mac={session.get('usermac')}, ip={session.get('userip')}"
        )

    return render_template(
        'submit.html',
        post_url=post_url,
        magic=magic,
        username=radius_user,
        password=SHARED_SECRET,
        display_name=friendly_name,
        group=tier,
        fallback=fallback,
        room=room,
    )


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=443,
        ssl_context=(
            os.environ.get('TLS_CERT', '/certs/portal.crt'),
            os.environ.get('TLS_KEY',  '/certs/portal.key'),
        ),
        debug=False
    )
