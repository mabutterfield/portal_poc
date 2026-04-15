import os
import logging
from flask import Flask, request, session, render_template

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-key-change-in-production')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

SHARED_SECRET = os.environ.get('SHARED_SECRET', 'ch4ng3m3')

# Maps the user's group selection to the RADIUS service account.
# FortiGate will forward these credentials to FreeRADIUS, which returns
# the Fortinet-Group-Name VSA to assign the correct policy group.
GROUP_MAP = {
    'free':    'svc_free',
    'premium': 'svc_premium',
}


@app.route('/auth')
def auth():
    """
    Entry point — FortiGate redirects unauthenticated clients here.

    Expected parameters from FortiGate:
      post      URL to POST credentials back to (FortiGate fgtauth endpoint)
      magic     Opaque session token — must be echoed back verbatim
      usermac   Client MAC address
      userip    Client IP address
      ssid      SSID name
      apname    AP name
      apmac     AP MAC
      apip      AP IP
      bssid     BSSID
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

    # Store FortiGate session parameters — needed when the form is submitted
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

    Validates inputs, maps the group selection to a RADIUS service account,
    then renders a hidden auto-submitting form that the client's browser
    POSTs directly to FortiGate's fgtauth endpoint.

    The auto-submit approach means the portal server does not need a direct
    route to FortiGate's internal interface — the client, who is already on
    that network, does the final POST.
    """
    display_name = request.form.get('username', '').strip()
    group        = request.form.get('group', '')

    ssid = session.get('ssid', '')

    if not display_name:
        return render_template('login.html', ssid=ssid, error='Please enter your name.')

    if group not in GROUP_MAP:
        return render_template('login.html', ssid=ssid, error='Please select an access type.')

    magic    = session.get('magic')
    post_url = session.get('post_url')

    if not magic or not post_url:
        logger.warning(f"Session expired for login attempt: name={display_name!r}")
        return render_template(
            'error.html',
            message='Your session has expired. Please reconnect to the network and try again.'
        )

    radius_user = GROUP_MAP[group]

    logger.info(
        f"Auth granted — name={display_name!r}, group={group}, "
        f"radius_user={radius_user}, mac={session.get('usermac')}, "
        f"ip={session.get('userip')}"
    )

    # Render the auto-submit page.
    # The client's browser will POST magic + service credentials to FortiGate.
    # FortiGate validates against FreeRADIUS, receives Fortinet-Group-Name,
    # assigns the policy group, and redirects the client to their original URL.
    return render_template(
        'submit.html',
        post_url=post_url,
        magic=magic,
        username=radius_user,
        password=SHARED_SECRET,
        display_name=display_name,
        group=group,
    )


if __name__ == '__main__':
    # Development only — in production gunicorn is used (see Dockerfile CMD)
    app.run(
        host='0.0.0.0',
        port=443,
        ssl_context=(
            os.environ.get('TLS_CERT', '/certs/portal.crt'),
            os.environ.get('TLS_KEY',  '/certs/portal.key'),
        ),
        debug=False
    )
