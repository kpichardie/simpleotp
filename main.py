import http.cookies
import http.server
import socketserver
import random
import time
from urllib.parse import parse_qs
import urllib.parse as urlparse
from cgi import parse_header, parse_multipart
import hashlib

import base64
import pyotp

import logging


logger = logging.getLogger('simpleOTP')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)

#COOKIEARREA="origindomain"
#COOKIEARREA="mydomain.fr"
COOKIEARREA="currentdomain"  # default behavior
PATH="/totp/"
PORT = 8000
TOKEN_LIFETIME = 60 * 60 * 24
LAST_LOGIN_ATTEMPT = 0
FORM = """
<html>
<head>
<title>Please Log In</title>
</head>
<body>
<div style="background-color: #333;width: 100%;height: 100%;position: absolute;top: 0px;left: 0px;">
<div style="background-color: #09F;color: white;font-size: 4em;font-style: italic;font-family: 'Open Sans';padding:0,75em;/* position: absolute; */top: 0px;left: 0px;width:100%;box-shadow: 2px 2px 3px #333;padding: 0.35em;" >
LOGIN SIMPLEOTP
</div>
<div style="background-color: #333; font-size: 3em;color: white;margin-top: 1em;margin-left: 1em;">
<form action="/auth/login" method="POST">
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;">
USER <input type="text" name="user">
</div>
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;">
PASS <input type="password" name="password">
</div>
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;">
TOKEN OTP <input type="text" name="token">
</div>
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;padding-left: 3em;">
<input type="submit" value="Submit" style="box-shadow:inset 0px 1px 0px 0px #ffffff;
	background:linear-gradient(to bottom, #ededed 5%, #dfdfdf 100%);
	background-color:#ededed;
	border-radius:6px;
	border:1px solid #dcdcdc;
	display:inline-block;
	cursor:pointer;
	color:#777777;
	font-family:Arial;
	font-size:15px;
	font-weight:bold;
	padding:6px 24px;
	text-decoration:none;
	text-shadow:0px 1px 0px #ffffff;">
</div>
</form>
</div>
</div>
</body>
</html>
"""
    
class TokenManager(object):
    """Who needs a database when you can just store everything in memory?"""

    def __init__(self):
        self.tokens = {}
        self.random = random.SystemRandom()

    def generate(self):
        t = '%064x' % self.random.getrandbits(8*32)
        self.tokens[t] = time.time()
        return t

    def is_valid(self, t):
        try:
            return time.time() - self.tokens.get(t, 0) < TOKEN_LIFETIME
        except Exception:
            return False

    def invalidate(self, t):
        if t in self.tokens:
            del self.tokens[t]

TOKEN_MANAGER = TokenManager()

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        logger.info(self.path)
        if self.path == '/auth/check':
            # Check if they have a valid token
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if 'token' in cookie and TOKEN_MANAGER.is_valid(cookie['token'].value):
                self.send_response(200)
                self.end_headers()
                return

            # Otherwise return 401, which will be redirected to '/auth/login' upstream
            self.send_response(401)
            self.end_headers()
            return

        if '/auth/login' in self.path:
            # Render out the login form
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(FORM, 'UTF-8'))
            return

        if self.path == '/auth/logout':
            # Invalidate any tokens
            cookie = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if 'token' in cookie:
                TOKEN_MANAGER.invalidate(cookie['token'].value)

            # This just replaces the token with garbage
            self.send_response(302)
            cookie = http.cookies.SimpleCookie()
            cookie["token"] = '***'
            cookie["token"]["path"] = '/'
            cookie["token"]["secure"] = True
            self.send_header('Set-Cookie', cookie.output(header=''))
            self.send_header('Location', '/')
            self.end_headers()
            return

        # Otherwise return 404
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        try:
            self.headers.get('Referer')
            referer=self.headers.get('Referer')
        except:
            referer='/auth/login'
        if '/auth/login' in self.path:
            # Rate limit login attempts to once per second
            global LAST_LOGIN_ATTEMPT
            if time.time() - LAST_LOGIN_ATTEMPT < 1.0:
                self.send_response(429)
                self.end_headers()
                self.wfile.write(bytes('Slow down. Hold your horses', 'UTF-8'))
                return
            LAST_LOGIN_ATTEMPT = time.time()

            # Check the TOTP Secret
            params = self.parse_POST()
            PASSWORDFILE = PATH + ".password_" + params.get(b'user')[0].decode() + "_secret"
            try: 
                PASSWORD = open(PASSWORDFILE).read().strip()
            except FileNotFoundError:
                self.send_response(302)
                self.send_header('Location', referer)
                self.end_headers()
                return
            SALTFILE = PATH + ".salt_" + params.get(b'user')[0].decode()
            try:
                SALT = open(SALTFILE).read().strip()
            except FileNotFoundError:
                self.send_response(302)
                self.send_header('Location', referer)
                self.end_headers()
                return
            logger.info("check login %s" % params.get(b'user')[0].decode())
            if not (hashlib.pbkdf2_hmac('sha256',params.get(b'password')[0].decode().encode('utf-8'),base64.b64decode(SALT),10000)) == base64.b64decode(PASSWORD):
                self.send_response(302)
                self.send_header('Location', referer)
                self.end_headers()
                return

            logger.info("check totp %s" % params.get(b'user')[0].decode())
            try:
                SECRET = open(PATH + '.totp_' + params.get(b'user')[0].decode() + '_secret').read().strip()
            except FileNotFoundError:
                self.send_response(302)
                self.send_header('Location', referer)
                self.end_headers()
                return
            if (params.get(b'token') or [None])[0] == bytes(pyotp.TOTP(SECRET).now(), 'UTF-8'):
                global COOKIEARREA
                if (COOKIEARREA == "origindomain"):
                   origin=self.headers.get('Origin')
                   separator="."
                   domain=separator.join(origin.split(".")[-2:])
                   cookie = http.cookies.SimpleCookie()
                   cookie["token"] = TOKEN_MANAGER.generate()
                   cookie["token"]["domain"] = domain
                   cookie["token"]["path"] = "/"
                   cookie["token"]["secure"] = True
                elif (COOKIEARREA != "currentdomain"):
                   cookie = http.cookies.SimpleCookie()
                   cookie["token"] = TOKEN_MANAGER.generate()
                   cookie["token"]["domain"] = COOKIEARREA
                   cookie["token"]["path"] = "/"
                   cookie["token"]["secure"] = True
                else:
                   cookie = http.cookies.SimpleCookie()
                   cookie["token"] = TOKEN_MANAGER.generate()
                   cookie["token"]["path"] = "/"
                   cookie["token"]["secure"] = True

                logger.info("Check query components")

                try:
                    query_components = urlparse.urlparse(referer)
                    origin_path=parse_qs(query_components.query)['orig_path']
                    orig_host='{uri.scheme}://{uri.netloc}'.format(uri=urlparse.urlparse(referer))
                    full_path = orig_host + origin_path[0]

                    self.send_response(302)
                    self.send_header('Set-Cookie', cookie.output(header=''))
                    if full_path == "auth/login?orig_path=/":
                        self.send_header('Location', '/')
                    else:
                        self.send_header('Location', full_path)
                    self.end_headers()
                    logger.info("sucess login %s" % params.get(b'user')[0].decode())
                    return
                except: 
                    self.send_response(302)
                    self.send_header('Set-Cookie', cookie.output(header=''))
                    self.send_header('Location', '/')
                    self.end_headers()
                    logger.info("sucess login %s" % params.get(b'user')[0].decode())
                    return


            # Otherwise redirect back to the login page
            else:
                self.send_response(302)
                self.send_header('Location', referer)
                self.end_headers()
                return
                
        # Otherwise return 404
        self.send_response(404)
        self.end_headers()

    def parse_POST(self):
        """Lifted from https://stackoverflow.com/questions/4233218/"""
        ctype, pdict = parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            postvars = parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['Content-Length'])
            postvars = parse_qs( self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}
        return postvars

socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("", PORT), AuthHandler, logger)
try:
    logger.info("serving at port %d", PORT)
    httpd.serve_forever()
finally:
    httpd.server_close()
