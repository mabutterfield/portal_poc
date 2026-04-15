"""
Mock PMS (Property Management System) service.

Provides a guest lookup API consumed by the captive portal, plus an admin
web UI for managing guest records and viewing query logs.

In production this container is replaced by an adapter to the real PMS
(Oracle Opera Cloud / Agilysys) — the portal's MOCK_PMS_URL env var is the
only thing that changes.

API
---
POST /api/lookup
    Body:  { room, last_name, mac, ip, nas_ip }
    200:   { found: true,  first_name, last_name, tier, checkout_dt }
    200:   { found: false }
    Every call is logged to the query_log table.

Admin UI
--------
GET  /admin                   Dashboard (guests + recent logs)
POST /admin/guests/add        Add a guest record
GET  /admin/guests/<id>/edit  Edit form
POST /admin/guests/<id>/edit  Save edit
POST /admin/guests/<id>/delete  Delete guest
GET  /admin/logs              Full log table (filterable)
POST /admin/logs/clear        Truncate query log
"""

import os
import sqlite3
import logging
import sys
from datetime import datetime, timedelta
from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, g, flash)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'pms-dev-key')

DB_PATH = os.environ.get('DB_PATH', '/data/pms.db')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and seed initial guest data if the DB is new."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row

    db.executescript("""
        CREATE TABLE IF NOT EXISTS guests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            room        TEXT    NOT NULL,
            last_name   TEXT    NOT NULL,
            first_name  TEXT    NOT NULL,
            tier        TEXT    NOT NULL DEFAULT 'free',
            checkout_dt TEXT,
            notes       TEXT,
            created_at  TEXT    DEFAULT (datetime('now')),
            updated_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS query_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              TEXT    DEFAULT (datetime('now')),
            room            TEXT,
            last_name_input TEXT,
            matched         INTEGER DEFAULT 0,
            matched_name    TEXT,
            returned_tier   TEXT,
            client_mac      TEXT,
            client_ip       TEXT,
            nas_ip          TEXT,
            status          TEXT,
            notes           TEXT
        );
    """)

    # Seed if empty
    count = db.execute('SELECT COUNT(*) FROM guests').fetchone()[0]
    if count == 0:
        logger.info("Seeding mock guest database...")
        today = datetime.now()
        # checkout_dt: most guests check out tomorrow at 11:00
        def co(days=1):
            return (today + timedelta(days=days)).strftime('%Y-%m-%d') + 'T11:00'

        seed = [
            # room  last_name     first_name   tier       checkout
            ('101', 'Anderson',   'James',     'free',    co(1)),
            ('102', 'Martinez',   'Sofia',     'premium', co(1)),
            ('201', 'Thompson',   'William',   'free',    co(2)),
            ('202', 'Garcia',     'Elena',     'premium', co(2)),
            ('301', 'Johnson',    'Robert',    'free',    co(1)),
            ('302', 'Williams',   'Patricia',  'premium', co(3)),
            ('401', 'Davis',      'Michael',   'free',    co(1)),
            ('402', 'Wilson',     'Jennifer',  'premium', co(2)),
            ('501', 'Brown',      'Christopher','premium',co(5)),
            ('502', 'Miller',     'Amanda',    'free',    co(1)),
        ]
        db.executemany(
            'INSERT INTO guests (room, last_name, first_name, tier, checkout_dt) '
            'VALUES (?, ?, ?, ?, ?)',
            seed,
        )
        db.commit()
        logger.info(f"Seeded {len(seed)} guest records.")

    db.close()


# ---------------------------------------------------------------------------
# Lookup API  (called by the captive portal)
# ---------------------------------------------------------------------------

@app.route('/api/lookup', methods=['POST'])
def api_lookup():
    data       = request.get_json(force=True, silent=True) or {}
    room       = (data.get('room',      '') or '').strip()
    last_name  = (data.get('last_name', '') or '').strip()
    mac        = data.get('mac',    '')
    ip         = data.get('ip',     '')
    nas_ip     = data.get('nas_ip', request.remote_addr)

    if not room or not last_name:
        _log_query(room, last_name, matched=False, mac=mac, ip=ip,
                   nas_ip=nas_ip, status='bad_request',
                   notes='Missing room or last_name')
        return jsonify({'found': False}), 200

    db = get_db()
    row = db.execute(
        'SELECT * FROM guests '
        'WHERE LOWER(TRIM(room)) = LOWER(TRIM(?)) '
        '  AND LOWER(TRIM(last_name)) = LOWER(TRIM(?)) '
        'LIMIT 1',
        (room, last_name),
    ).fetchone()

    if row:
        logger.info(
            f"Lookup HIT — room={room!r}, last_name={last_name!r}, "
            f"tier={row['tier']!r}, mac={mac}, ip={ip}"
        )
        _log_query(room, last_name, matched=True,
                   matched_name=f"{row['first_name']} {row['last_name']}",
                   returned_tier=row['tier'],
                   mac=mac, ip=ip, nas_ip=nas_ip, status='matched')
        return jsonify({
            'found':       True,
            'first_name':  row['first_name'],
            'last_name':   row['last_name'],
            'tier':        row['tier'],
            'checkout_dt': row['checkout_dt'],
        })
    else:
        logger.info(
            f"Lookup MISS — room={room!r}, last_name={last_name!r}, "
            f"mac={mac}, ip={ip}"
        )
        _log_query(room, last_name, matched=False,
                   mac=mac, ip=ip, nas_ip=nas_ip, status='not_found')
        return jsonify({'found': False})


def _log_query(room, last_name_input, *, matched, mac='', ip='',
               nas_ip='', returned_tier=None, matched_name=None,
               status='', notes=''):
    try:
        db = get_db()
        db.execute(
            'INSERT INTO query_log '
            '(room, last_name_input, matched, matched_name, returned_tier, '
            ' client_mac, client_ip, nas_ip, status, notes) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (room, last_name_input, 1 if matched else 0, matched_name,
             returned_tier, mac, ip, nas_ip, status, notes),
        )
        db.commit()
    except Exception as exc:
        logger.error(f"Failed to write query log: {exc}")


# ---------------------------------------------------------------------------
# Admin UI
# ---------------------------------------------------------------------------

@app.route('/admin')
def admin():
    db = get_db()
    guests = db.execute(
        'SELECT * FROM guests ORDER BY CAST(room AS INTEGER), room'
    ).fetchall()
    logs = db.execute(
        'SELECT * FROM query_log ORDER BY id DESC LIMIT 50'
    ).fetchall()
    return render_template('admin.html', guests=guests, logs=logs,
                           page='dashboard')


@app.route('/admin/guests/add', methods=['POST'])
def guest_add():
    db = get_db()
    db.execute(
        'INSERT INTO guests (room, last_name, first_name, tier, checkout_dt, notes) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (
            request.form.get('room', '').strip(),
            request.form.get('last_name', '').strip(),
            request.form.get('first_name', '').strip(),
            request.form.get('tier', 'free'),
            request.form.get('checkout_dt', '').strip() or None,
            request.form.get('notes', '').strip() or None,
        ),
    )
    db.commit()
    flash('Guest added.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/guests/<int:guest_id>/edit', methods=['GET', 'POST'])
def guest_edit(guest_id):
    db = get_db()
    if request.method == 'POST':
        db.execute(
            'UPDATE guests SET room=?, last_name=?, first_name=?, tier=?, '
            'checkout_dt=?, notes=?, updated_at=datetime("now") WHERE id=?',
            (
                request.form.get('room', '').strip(),
                request.form.get('last_name', '').strip(),
                request.form.get('first_name', '').strip(),
                request.form.get('tier', 'free'),
                request.form.get('checkout_dt', '').strip() or None,
                request.form.get('notes', '').strip() or None,
                guest_id,
            ),
        )
        db.commit()
        flash('Guest updated.', 'success')
        return redirect(url_for('admin'))

    guest = db.execute('SELECT * FROM guests WHERE id=?', (guest_id,)).fetchone()
    if not guest:
        flash('Guest not found.', 'danger')
        return redirect(url_for('admin'))
    return render_template('admin.html', edit_guest=guest, page='edit')


@app.route('/admin/guests/<int:guest_id>/delete', methods=['POST'])
def guest_delete(guest_id):
    db = get_db()
    db.execute('DELETE FROM guests WHERE id=?', (guest_id,))
    db.commit()
    flash('Guest deleted.', 'warning')
    return redirect(url_for('admin'))


@app.route('/admin/logs')
def admin_logs():
    db    = get_db()
    # Optional filters
    froom  = request.args.get('room', '').strip()
    fstatus = request.args.get('status', '').strip()

    query  = 'SELECT * FROM query_log WHERE 1=1'
    params = []
    if froom:
        query += ' AND LOWER(room) = LOWER(?)'
        params.append(froom)
    if fstatus:
        query += ' AND status = ?'
        params.append(fstatus)
    query += ' ORDER BY id DESC LIMIT 200'

    logs = db.execute(query, params).fetchall()
    return render_template('admin.html', logs=logs, page='logs',
                           filter_room=froom, filter_status=fstatus)


@app.route('/admin/logs/clear', methods=['POST'])
def logs_clear():
    db = get_db()
    db.execute('DELETE FROM query_log')
    db.commit()
    flash('Query log cleared.', 'warning')
    return redirect(url_for('admin_logs'))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)


# Initialize DB on first import (gunicorn workers call this on load)
with app.app_context():
    init_db()
