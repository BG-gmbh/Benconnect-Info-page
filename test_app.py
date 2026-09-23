import os,tempfile,re,unittest,smtplib
from unittest.mock import patch
os.environ.update(SECRET_KEY='test-key-only',ADMIN_INITIAL_PASSWORD='test-password-very-long',DATABASE_PATH=tempfile.mktemp(),SMTP_HOST='example.invalid',SMTP_USER='sender@example.org',SMTP_PASSWORD='test',SMTP_FROM='sender@example.org',CONTACT_TO='contact@example.org')
import app as site
site.app.config.update(TESTING=True,SESSION_COOKIE_SECURE=False,WTF_CSRF_SSL_STRICT=False)
class Tests(unittest.TestCase):
 def setUp(self):
  self.c=site.app.test_client()
  with site.db() as d:d.execute('DELETE FROM attempts')
 def token(self,path='/'):
  r=self.c.get(path);self.assertEqual(r.status_code,200)
  return re.search(r'name="csrf_token" value="([^"]+)"',r.text).group(1)
 def post(self,path,data):return self.c.post(path,data=data,headers={'Referer':'http://localhost/'})
 def test_contact(self):
  data=dict(csrf_token=self.token(),name='Test User',email='user@example.org',subject='Test message',message='This is a sufficiently long test.',consent='yes')
  with patch('app.smtplib.SMTP_SSL') as smtp:
   self.assertEqual(self.post('/contact',data).status_code,303)
   message=smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
   self.assertEqual(message['To'],'contact@example.org');self.assertEqual(message['Reply-To'],'user@example.org')
  with patch('app.smtplib.SMTP_SSL',side_effect=smtplib.SMTPException()):
   r=self.post('/contact',data);self.assertEqual(r.status_code,503);self.assertIn(data['message'],r.text)
 def test_csrf_and_validation(self):
  self.assertEqual(self.post('/contact',{}).status_code,400)
  self.assertEqual(self.post('/contact',dict(csrf_token=self.token(),name='a')).status_code,400)
 def test_admin(self):
  self.assertEqual(self.c.get('/admin').status_code,302)
  token=self.token('/admin/login')
  self.assertEqual(self.post('/admin/login',dict(csrf_token=token,password='wrong')).status_code,401)
  self.assertEqual(self.post('/admin/login',dict(csrf_token=token,password='test-password-very-long')).status_code,303)
  data={f['key']:f['default'] for f in site.FIELDS};data['text_0']='<script>alert(1)</script>';data['csrf_token']=self.token('/admin')
  self.assertEqual(self.post('/admin',data).status_code,303)
  self.assertIn('&lt;script&gt;',self.c.get('/').text)
  self.assertEqual(site.contents()['text_0'],data['text_0'])
  t=self.token('/admin');self.assertEqual(self.post('/admin/logout',dict(csrf_token=t)).status_code,303)
  self.assertEqual(self.c.get('/admin').status_code,302)
 def test_rate_limit(self):
  t=self.token('/admin/login')
  for _ in range(10):self.post('/admin/login',dict(csrf_token=t,password='wrong'))
  self.assertEqual(self.post('/admin/login',dict(csrf_token=t,password='wrong')).status_code,429)
if __name__=='__main__':unittest.main()
