"""
Revive — app.py
Flask Backend: Auth, Lessons, Revisions, Analytics, Email, n8n Webhook
Database: database.json (flat-file, no MongoDB needed for Replit)
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import json, os, hashlib, hmac, uuid, time, threading
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

DB_FILE = 'database.json'

# ===================== DATABASE =====================
def load_db():
    if not os.path.exists(DB_FILE):
        save_db({'users': {}, 'lessons': {}, 'revisions': {}, 'sessions': [], 'config': {}})
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=2, default=str)

def init_db():
    if not os.path.exists(DB_FILE):
        save_db({'users': {}, 'lessons': {}, 'revisions': {}, 'sessions': [], 'config': {}})

# ===================== AUTH HELPERS =====================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token(user_id):
    raw = f"{user_id}:{time.time()}:{uuid.uuid4()}"
    return hashlib.sha256(raw.encode()).hexdigest()

def get_user_from_token(token):
    db = load_db()
    for uid, user in db['users'].items():
        if user.get('token') == token:
            return user
    return None

def auth_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        user = get_user_from_token(token)
        if not user:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        request.user = user
        return f(*args, **kwargs)
    return decorated

# ===================== STATIC FILES =====================
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)

# ===================== AUTH ROUTES =====================
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not all([name, email, password]):
        return jsonify({'success': False, 'message': 'All fields required'}), 400

    db = load_db()

    # Check duplicate
    for uid, user in db['users'].items():
        if user.get('email') == email:
            return jsonify({'success': False, 'message': 'Email already registered'}), 409

    user_id = str(uuid.uuid4())
    token = generate_token(user_id)

    db['users'][user_id] = {
        'id': user_id,
        'name': name,
        'email': email,
        'password': hash_password(password),
        'token': token,
        'created_at': datetime.now().isoformat(),
        'streak': 0,
        'focusTime': 0,
    }
    save_db(db)

    return jsonify({
        'success': True,
        'token': token,
        'user': {'id': user_id, 'name': name, 'email': email}
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    db = load_db()
    for uid, user in db['users'].items():
        if user.get('email') == email and user.get('password') == hash_password(password):
            token = generate_token(uid)
            db['users'][uid]['token'] = token
            db['users'][uid]['last_login'] = datetime.now().isoformat()
            save_db(db)
            return jsonify({
                'success': True,
                'token': token,
                'user': {'id': uid, 'name': user['name'], 'email': user['email']}
            })

    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/api/auth/me', methods=['GET'])
@auth_required
def get_me():
    return jsonify({'success': True, 'user': {
        'id': request.user['id'],
        'name': request.user['name'],
        'email': request.user['email'],
    }})

# ===================== LESSON ROUTES =====================
@app.route('/api/lessons', methods=['GET'])
@auth_required
def get_lessons():
    db = load_db()
    user_id = request.user['id']
    lessons = [l for l in db['lessons'].values() if l.get('userId') == user_id]
    lessons.sort(key=lambda l: l.get('addedAt', ''), reverse=True)
    return jsonify({'success': True, 'lessons': lessons})

@app.route('/api/lessons', methods=['POST'])
@auth_required
def add_lesson():
    data = request.json or {}
    db = load_db()
    user_id = request.user['id']
    demo_mode = data.get('demoMode', False)

    lesson_id = data.get('id') or str(uuid.uuid4())

    lesson = {
        'id': lesson_id,
        'userId': user_id,
        'title': data.get('title', '').strip(),
        'subject': data.get('subject', 'General').strip(),
        'priority': data.get('priority', 'medium'),
        'notes': data.get('notes', ''),
        'addedAt': datetime.now().isoformat(),
        'retention': 100,
        'revisionsDone': 0,
        'nextRevisionIndex': 0,
    }

    if not lesson['title']:
        return jsonify({'success': False, 'message': 'Title required'}), 400

    db['lessons'][lesson_id] = lesson

    # Schedule revisions
    revisions = schedule_revisions(lesson_id, lesson['title'], user_id, demo_mode)
    for rev in revisions:
        db['revisions'][rev['id']] = rev

    save_db(db)

    # Trigger email in background
    email_cfg = db.get('config', {}).get('email')
    if email_cfg:
        threading.Thread(target=send_lesson_email,
            args=(email_cfg, request.user['email'], lesson['title'])).start()

    log_automation(db, f"Lesson added: {lesson['title']} | {len(revisions)} revisions scheduled")

    return jsonify({'success': True, 'lesson': lesson, 'revisions': revisions})

@app.route('/api/lessons/<lesson_id>', methods=['DELETE'])
@auth_required
def delete_lesson(lesson_id):
    db = load_db()
    user_id = request.user['id']
    if lesson_id in db['lessons'] and db['lessons'][lesson_id]['userId'] == user_id:
        del db['lessons'][lesson_id]
        # Remove associated revisions
        to_del = [rid for rid, r in db['revisions'].items() if r['lessonId'] == lesson_id]
        for rid in to_del: del db['revisions'][rid]
        save_db(db)
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Not found'}), 404

# ===================== REVISION ROUTES =====================
@app.route('/api/revisions', methods=['GET'])
@auth_required
def get_revisions():
    db = load_db()
    user_id = request.user['id']
    revisions = [r for r in db['revisions'].values() if r.get('userId') == user_id]
    revisions.sort(key=lambda r: r.get('scheduledAt', ''))
    return jsonify({'success': True, 'revisions': revisions})

@app.route('/api/revisions/due', methods=['GET'])
@auth_required
def get_due_revisions():
    db = load_db()
    user_id = request.user['id']
    now = datetime.now().isoformat()
    due = [r for r in db['revisions'].values()
           if r.get('userId') == user_id
           and r.get('status') == 'pending'
           and r.get('scheduledAt', '') <= now]
    return jsonify({'success': True, 'revisions': due, 'count': len(due)})

@app.route('/api/revisions/<rev_id>/complete', methods=['POST'])
@auth_required
def complete_revision(rev_id):
    data = request.json or {}
    result = data.get('result', 'remembered')  # 'remembered' | 'forgot'
    db = load_db()

    if rev_id not in db['revisions']:
        return jsonify({'success': False, 'message': 'Revision not found'}), 404

    rev = db['revisions'][rev_id]
    rev['status'] = 'completed'
    rev['result'] = result
    rev['completedAt'] = datetime.now().isoformat()

    # Update lesson retention
    lesson_id = rev.get('lessonId')
    if lesson_id and lesson_id in db['lessons']:
        lesson = db['lessons'][lesson_id]
        if result == 'remembered':
            lesson['retention'] = min(100, lesson.get('retention', 50) + 20)
        else:
            lesson['retention'] = max(10, lesson.get('retention', 100) - 30)
        lesson['revisionsDone'] = lesson.get('revisionsDone', 0) + 1

    # Adaptive: schedule retry if forgotten
    if result == 'forgot':
        demo_mode = data.get('demoMode', False)
        retry_delay = 1 if demo_mode else 60  # 1 min demo, 1 hour real
        retry_rev = {
            'id': f"rev_retry_{rev_id}_{int(time.time())}",
            'lessonId': rev['lessonId'],
            'lessonTitle': rev['lessonTitle'],
            'userId': rev['userId'],
            'intervalIndex': rev['intervalIndex'],
            'intervalLabel': '↩ Retry',
            'scheduledAt': (datetime.now() + timedelta(minutes=retry_delay)).isoformat(),
            'status': 'pending',
            'result': None,
        }
        db['revisions'][retry_rev['id']] = retry_rev

    save_db(db)
    return jsonify({'success': True, 'result': result})

# ===================== ANALYTICS ROUTES =====================
@app.route('/api/analytics', methods=['GET'])
@auth_required
def get_analytics():
    db = load_db()
    user_id = request.user['id']

    lessons = [l for l in db['lessons'].values() if l.get('userId') == user_id]
    revisions = [r for r in db['revisions'].values() if r.get('userId') == user_id]
    sessions = [s for s in db.get('sessions', []) if s.get('userId') == user_id]

    completed_revs = [r for r in revisions if r.get('status') == 'completed']
    remembered = [r for r in completed_revs if r.get('result') == 'remembered']

    total_focus = sum(s.get('duration', 0) for s in sessions)
    avg_retention = (sum(l.get('retention', 0) for l in lessons) / len(lessons)) if lessons else 0
    completion_rate = (len(completed_revs) / len(revisions) * 100) if revisions else 0
    accuracy = (len(remembered) / len(completed_revs) * 100) if completed_revs else 0

    return jsonify({
        'success': True,
        'analytics': {
            'totalLessons': len(lessons),
            'totalRevisions': len(revisions),
            'completedRevisions': len(completed_revs),
            'completionRate': round(completion_rate, 1),
            'accuracy': round(accuracy, 1),
            'avgRetention': round(avg_retention, 1),
            'totalFocusMinutes': total_focus,
            'productivityScore': round((completion_rate + accuracy) / 2),
        }
    })

# ===================== SESSION ROUTES =====================
@app.route('/api/sessions', methods=['POST'])
@auth_required
def add_session():
    data = request.json or {}
    db = load_db()
    session = {
        'id': str(uuid.uuid4()),
        'userId': request.user['id'],
        'lessonId': data.get('lessonId'),
        'lessonTitle': data.get('lessonTitle', 'Free Focus'),
        'duration': data.get('duration', 25),
        'at': datetime.now().isoformat(),
    }
    if 'sessions' not in db:
        db['sessions'] = []
    db['sessions'].append(session)
    save_db(db)
    return jsonify({'success': True, 'session': session})

# ===================== EMAIL CONFIG =====================
@app.route('/api/config/email', methods=['POST'])
@auth_required
def save_email_config():
    data = request.json or {}
    db = load_db()
    if 'config' not in db:
        db['config'] = {}
    db['config']['email'] = {
        'host': data.get('host', 'smtp.gmail.com'),
        'port': 587,
        'email': data.get('email', ''),
        'password': data.get('password', ''),
    }
    save_db(db)

    # Test connection
    cfg = db['config']['email']
    try:
        send_test_email(cfg)
        return jsonify({'success': True, 'message': 'Config saved. Test email sent!'})
    except Exception as e:
        return jsonify({'success': True, 'message': f'Config saved. Email test failed: {str(e)}'})

# ===================== n8n WEBHOOK =====================
@app.route('/api/webhook/n8n', methods=['POST'])
def n8n_webhook():
    """Receives n8n workflow data — lesson added / revision due"""
    data = request.json or {}
    event = data.get('event')
    db = load_db()

    if event == 'lesson_added':
        log_automation(db, f"[n8n webhook] Lesson added: {data.get('lessonTitle')}")
    elif event == 'revision_due':
        log_automation(db, f"[n8n webhook] Revision due: {data.get('lessonTitle')}")
    elif event == 'reminder_sent':
        log_automation(db, f"[n8n webhook] Reminder sent: {data.get('lessonTitle')}")

    save_db(db)
    return jsonify({'success': True, 'received': event})

@app.route('/api/automation/log', methods=['GET'])
@auth_required
def get_automation_log():
    db = load_db()
    return jsonify({'success': True, 'log': db.get('automation_log', [])[-50:]})

# ===================== HELPERS =====================
def schedule_revisions(lesson_id, lesson_title, user_id, demo_mode=False):
    """Compute revision schedule using Ebbinghaus intervals"""
    intervals_real  = [0, 3 * 24 * 60, 10 * 24 * 60]   # minutes
    intervals_demo  = [0.5, 3, 10]                        # demo minutes
    labels          = ['Immediate', '3-Day', '10-Day']
    intervals       = intervals_demo if demo_mode else intervals_real

    now = datetime.now()
    revisions = []

    for i, delay_min in enumerate(intervals):
        scheduled = now + timedelta(minutes=delay_min)
        rev = {
            'id': f"rev_{lesson_id}_{i}_{int(time.time())}",
            'lessonId': lesson_id,
            'lessonTitle': lesson_title,
            'userId': user_id,
            'intervalIndex': i,
            'intervalLabel': labels[i],
            'scheduledAt': scheduled.isoformat(),
            'status': 'pending',
            'result': None,
            'demoMode': demo_mode,
        }
        revisions.append(rev)
    return revisions

def log_automation(db, message):
    if 'automation_log' not in db:
        db['automation_log'] = []
    db['automation_log'].append({
        'ts': datetime.now().isoformat(),
        'msg': message
    })

def send_lesson_email(cfg, to_email, lesson_title):
    """Send email notification via SMTP"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'📚 New Lesson Added: {lesson_title}'
        msg['From'] = cfg['email']
        msg['To'] = to_email

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#0a0c12;color:#e8ecf5;padding:32px;border-radius:12px">
          <h2 style="color:#4f9fff">📚 Lesson Scheduled!</h2>
          <p style="color:#8892aa">Your lesson <strong style="color:#e8ecf5">{lesson_title}</strong> has been added to Revive.</p>
          <div style="background:#151825;border:1px solid #232840;border-radius:8px;padding:16px;margin:20px 0">
            <p style="color:#8892aa;margin:0 0 8px">Revision Schedule:</p>
            <ul style="color:#e8ecf5;margin:0;padding-left:20px">
              <li>✅ Immediate review</li>
              <li>📅 3-day revision</li>
              <li>📆 10-day revision</li>
            </ul>
          </div>
          <p style="color:#4a5270;font-size:12px">Powered by Ebbinghaus Spaced Repetition</p>
        </div>"""

        msg.attach(MIMEText(html, 'html'))
        server = smtplib.SMTP(cfg['host'], cfg.get('port', 587))
        server.starttls()
        server.login(cfg['email'], cfg['password'])
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Email error: {e}")

def send_revision_email(cfg, to_email, lesson_title, interval_label):
    """Send revision reminder email"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'🔔 Revise: {lesson_title} – {interval_label}'
        msg['From'] = cfg['email']
        msg['To'] = to_email

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;background:#0a0c12;color:#e8ecf5;padding:32px;border-radius:12px">
          <h2 style="color:#ff9f4f">🔔 Revision Reminder</h2>
          <p style="color:#8892aa">It's time to revise:</p>
          <div style="background:#1a1600;border:1px solid rgba(255,159,79,0.3);border-radius:8px;padding:20px;margin:16px 0;text-align:center">
            <h3 style="color:#ff9f4f;margin:0 0 8px">{lesson_title}</h3>
            <span style="background:rgba(255,159,79,0.2);color:#ff9f4f;padding:4px 12px;border-radius:20px;font-size:12px">{interval_label} Review</span>
          </div>
          <p style="color:#8892aa;font-size:13px">Open Revive to complete your revision and track your retention score.</p>
          <p style="color:#4a5270;font-size:11px;margin-top:24px">Based on Ebbinghaus Forgetting Curve | Revive</p>
        </div>"""

        msg.attach(MIMEText(html, 'html'))
        server = smtplib.SMTP(cfg['host'], cfg.get('port', 587))
        server.starttls()
        server.login(cfg['email'], cfg['password'])
        server.send_message(msg)
        server.quit()
        print(f"Revision email sent to {to_email}: {lesson_title}")
    except Exception as e:
        print(f"Email error: {e}")

def send_test_email(cfg):
    msg = MIMEText('<h2>Revive email is working! 🎉</h2>', 'html')
    msg['Subject'] = '✅ Revive Email Test'
    msg['From'] = cfg['email']
    msg['To'] = cfg['email']
    server = smtplib.SMTP(cfg['host'], cfg.get('port', 587))
    server.starttls()
    server.login(cfg['email'], cfg['password'])
    server.send_message(msg)
    server.quit()

# ===================== BACKGROUND SCHEDULER =====================
def revision_checker():
    """Runs in background to check for due revisions and send emails"""
    while True:
        try:
            db = load_db()
            now = datetime.now().isoformat()
            cfg = db.get('config', {}).get('email')

            for rev_id, rev in list(db['revisions'].items()):
                if rev.get('status') == 'pending' and rev.get('scheduledAt', '') <= now:
                    if not rev.get('notified'):
                        # Mark as notified
                        db['revisions'][rev_id]['notified'] = True
                        log_automation(db, f"[AUTO] Revision due: {rev['lessonTitle']} [{rev['intervalLabel']}]")

                        # Send email if configured
                        if cfg:
                            # Find user email
                            user = db['users'].get(rev.get('userId', ''))
                            if user:
                                threading.Thread(
                                    target=send_revision_email,
                                    args=(cfg, user['email'], rev['lessonTitle'], rev['intervalLabel'])
                                ).start()
                                log_automation(db, f"[EMAIL] Sent: Revise: {rev['lessonTitle']}")

            save_db(db)
        except Exception as e:
            print(f"Scheduler error: {e}")
        time.sleep(30)  # Check every 30 seconds

# ===================== n8n WORKFLOW JSON =====================
@app.route('/api/n8n/workflow', methods=['GET'])
def get_n8n_workflow():
    """Returns the n8n workflow JSON for import"""
    workflow = {
        "name": "Revive - Spaced Repetition Automation",
        "nodes": [
            {
                "parameters": {"path": "/lesson-added", "httpMethod": "POST"},
                "name": "Webhook - Lesson Added",
                "type": "n8n-nodes-base.webhook",
                "position": [250, 300]
            },
            {
                "parameters": {
                    "url": "http://localhost:5000/api/lessons",
                    "method": "POST",
                    "bodyParametersUi": {
                        "parameter": [
                            {"name": "title", "value": "={{$json.lessonTitle}}"},
                            {"name": "demoMode", "value": "={{$json.demoMode}}"}
                        ]
                    }
                },
                "name": "HTTP - Store Lesson",
                "type": "n8n-nodes-base.httpRequest",
                "position": [450, 300]
            },
            {
                "parameters": {"amount": 3, "unit": "minutes"},
                "name": "Wait - 3 min (3 days)",
                "type": "n8n-nodes-base.wait",
                "position": [650, 300]
            },
            {
                "parameters": {
                    "fromEmail": "=YOUR_EMAIL",
                    "toEmail": "={{$json.userEmail}}",
                    "subject": "=Revise: {{$json.lessonTitle}} - 3-Day Review",
                    "text": "=Time to revise: {{$json.lessonTitle}}. Open Revive to complete your review."
                },
                "name": "Email - 3 Day Reminder",
                "type": "n8n-nodes-base.emailSend",
                "position": [850, 300]
            }
        ],
        "connections": {
            "Webhook - Lesson Added": {"main": [[{"node": "HTTP - Store Lesson"}]]},
            "HTTP - Store Lesson": {"main": [[{"node": "Wait - 3 min (3 days)"}]]},
            "Wait - 3 min (3 days)": {"main": [[{"node": "Email - 3 Day Reminder"}]]}
        }
    }
    return jsonify(workflow)

# ===================== MAIN =====================
if __name__ == '__main__':
    init_db()
    # Start background revision checker
    checker = threading.Thread(target=revision_checker, daemon=True)
    checker.start()
    print("🚀 Revive server starting on port 5000...")
    print("📧 Email reminders: Configure via /api/config/email")
    print("⚡ n8n Webhook: POST /api/webhook/n8n")
    print("📊 n8n Workflow JSON: GET /api/n8n/workflow")
    app.run(host='0.0.0.0', port=5000, debug=True)
