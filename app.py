import os, json, sqlite3, secrets, time, smtplib, ssl, hashlib
from datetime import timedelta
from pathlib import Path
from email.message import EmailMessage
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, flash, abort
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ['SECRET_KEY'], MAX_CONTENT_LENGTH=65536,
 SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
 PERMANENT_SESSION_LIFETIME=timedelta(hours=2), WTF_CSRF_TIME_LIMIT=7200)
CSRFProtect(app)
DB=os.getenv('DATABASE_PATH','/data/site.db')
FIELDS=json.loads(Path('fields.json').read_text())

def db():
 c=sqlite3.connect(DB,timeout=15); c.row_factory=sqlite3.Row; return c

def init():
 Path(DB).parent.mkdir(parents=True,exist_ok=True)
 with db() as c:
  c.executescript('CREATE TABLE IF NOT EXISTS content (key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY,password TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1); CREATE TABLE IF NOT EXISTS attempts (bucket TEXT,time REAL); CREATE INDEX IF NOT EXISTS attempts_bucket ON attempts(bucket,time);')
  if not c.execute('SELECT id FROM admin').fetchone():
   p=os.environ.get('ADMIN_INITIAL_PASSWORD')
   if not p or len(p)<16:raise RuntimeError('Set a strong ADMIN_INITIAL_PASSWORD')
   c.execute('INSERT OR IGNORE INTO admin(id,password) VALUES(1,?)',(generate_password_hash(p),))
init()

def limited(action,maximum,window):
 # Host nginx overwrites X-Real-IP; app port is restricted to loopback.
 ip=request.headers.get('X-Real-IP',request.remote_addr)
 bucket=hashlib.sha256((action+ip).encode()).hexdigest(); now=time.time()
 with db() as c:
  c.execute('BEGIN IMMEDIATE');c.execute('DELETE FROM attempts WHERE time < ?',(now-3600,))
  n=c.execute('SELECT COUNT(*) FROM attempts WHERE bucket=? AND time>?',(bucket,now-window)).fetchone()[0]
  if n>=maximum:return True
  c.execute('INSERT INTO attempts VALUES(?,?)',(bucket,now))
 return False

def admin_required(fn):
 @wraps(fn)
 def wrapped(*a,**kw):
  with db() as c:r=c.execute('SELECT version FROM admin WHERE id=1').fetchone()
  if session.get('admin_version')!=r['version']:return redirect(url_for('login'))
  return fn(*a,**kw)
 return wrapped

def contents():
 result={f['key']:f['default'] for f in FIELDS}
 with db() as c:result.update({r['key']:r['value'] for r in c.execute('SELECT key,value FROM content')})
 return result

@app.after_request
def headers(r):
 r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY'
 r.headers['Referrer-Policy']='strict-origin-when-cross-origin'
 r.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
 if request.path!='/static/style.css':r.headers['Cache-Control']='no-store'
 return r

@app.get('/')
def home():return render_template('index.html',c=contents())

@app.post('/contact')
def contact():
 values={k:request.form.get(k,'').strip() for k in ['name','email','subject','message']}
 def invalid(message,status=400):return render_template('index.html',c=contents(),form_error=message,values=values),status
 if request.form.get('website'):return invalid('Bitte versuche es erneut.')
 if limited('contact',5,3600):return invalid('Zu viele Anfragen. Bitte versuche es in einer Stunde erneut.',429)
 if not 2<=len(values['name'])<=100 or not 3<=len(values['subject'])<=150 or not 10<=len(values['message'])<=5000:return invalid('Bitte fülle alle Felder aus. Die Nachricht muss 10 bis 5.000 Zeichen enthalten.')
 if any('\n' in values[k] or '\r' in values[k] for k in ['name','email','subject']):return invalid('Ungültige Eingabe.')
 try:values['email']=validate_email(values['email'],check_deliverability=False).normalized
 except EmailNotValidError:return invalid('Bitte gib eine gültige E-Mail-Adresse ein.')
 if request.form.get('consent')!='yes':return invalid('Bitte bestätige die Verarbeitung deiner Angaben zur Beantwortung der Anfrage.')
 msg=EmailMessage();msg['From']=os.environ['SMTP_FROM'];msg['To']=os.environ['CONTACT_TO'];msg['Reply-To']=values['email'];msg['Subject']='Benconnect Kontakt: '+values['subject']
 msg.set_content('Kontaktanfrage über benconnect.info\n\nName: '+values['name']+'\nE-Mail: '+values['email']+'\n\n'+values['message'])
 try:
  with smtplib.SMTP_SSL(os.environ['SMTP_HOST'],int(os.getenv('SMTP_PORT','465')),timeout=20,context=ssl.create_default_context()) as smtp:
   smtp.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD']);smtp.send_message(msg)
 except (OSError,smtplib.SMTPException):
  app.logger.error('Contact email delivery failed')
  return invalid('Der Versand ist gerade nicht möglich. Deine Eingaben bleiben erhalten. Bitte versuche es erneut oder schreibe direkt an Contact@benconnect.info.',503)
 flash('Deine Nachricht wurde an unseren Mailserver übergeben. Vielen Dank!','success')
 return redirect(url_for('home')+'#kontakt',code=303)

@app.route('/admin/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  if limited('login',10,900):return render_template('login.html',error='Zu viele Versuche. Bitte warte 15 Minuten.'),429
  with db() as c:r=c.execute('SELECT * FROM admin WHERE id=1').fetchone()
  if check_password_hash(r['password'],request.form.get('password','')):
   session.clear();session['admin_version']=r['version'];session.permanent=True;return redirect(url_for('admin'),code=303)
  return render_template('login.html',error='Das Passwort ist nicht korrekt.'),401
 return render_template('login.html')

@app.route('/admin',methods=['GET','POST'])
@admin_required
def admin():
 if request.method=='POST':
  changes={f['key']:request.form.get(f['key'],'').strip() for f in FIELDS}
  if any(not v or len(v)>2000 for v in changes.values()):
   return render_template('admin.html',fields=FIELDS,c=changes,error='Jedes Feld benötigt 1 bis 2.000 Zeichen.'),400
  with db() as conn:
   conn.executemany('INSERT INTO content VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',changes.items())
  flash('Inhalte gespeichert. Sie sind jetzt auf der Website sichtbar.','success');return redirect(url_for('admin'),code=303)
 return render_template('admin.html',fields=FIELDS,c=contents())

@app.post('/admin/password')
@admin_required
def password():
 with db() as c:r=c.execute('SELECT * FROM admin WHERE id=1').fetchone()
 new=request.form.get('new_password','')
 if not check_password_hash(r['password'],request.form.get('current_password','')) or len(new)<16 or len(new)>256 or new!=request.form.get('confirm_password'):
  flash('Passwort nicht geändert: aktuelles Passwort prüfen, mindestens 16 Zeichen verwenden und Bestätigung abgleichen.','error')
 else:
  with db() as c:c.execute('UPDATE admin SET password=?,version=version+1 WHERE id=1',(generate_password_hash(new),))
  session.clear();flash('Passwort geändert. Bitte erneut anmelden.','success');return redirect(url_for('login'),code=303)
 return redirect(url_for('admin'),code=303)

@app.post('/admin/logout')
def logout():session.clear();return redirect(url_for('login'),code=303)

@app.get('/health')
def health():
 with db() as c:c.execute('SELECT 1')
 return 'ok\n'
