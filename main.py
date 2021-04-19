import http.cookies
import http.server
import socketserver
import random
import time
from urllib.parse import parse_qs
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
LOGIN
<form action="/auth/login" method="POST">
USER <input type="text" name="user">
PASS <input type="text" type="password" name="password">
TOKEN OTP <input type="text" name="token">
<input type="submit" value="Submit">
</form>
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
            logger.info(self.headers.get('Referer'))
            referer=self.headers.get('Referer')
        except:
            logger.info('no referer')
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
            logger.info(params)
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
                cookie = http.cookies.SimpleCookie()
                cookie["token"] = TOKEN_MANAGER.generate()
                cookie["token"]["path"] = "/"
                cookie["token"]["secure"] = True

                query_components = parse_qs(urlparse(self.path).query)
                full_path="https://" + self.headers.get('Host') + origin_path
                logger.info(full_path)

                origin_path=query_components["orig_path"]

                try:
                    query_components = parse_qs(urlparse(self.path).query)
                    
                    origin_path=query_components["orig_path"]
                    full_path="https://" + self.headers.get('Host') + origin_path

                    self.send_response(302)
                    self.send_header('Set-Cookie', cookie.output(header=''))
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
