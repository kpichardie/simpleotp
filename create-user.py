import http.cookies
import http.server
import socketserver
import random
import time
from urllib.parse import parse_qs
from cgi import parse_header, parse_multipart
import hashlib
import os

import pyqrcode

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

PATH = "/totp/"
PORT = 8000
TOKEN_LIFETIME = 60 * 60 * 24
LAST_LOGIN_ATTEMPT = 0
FORM = """
<html>
<head>
<title>Gen totp user</title>
</head>
<body>
AUTH GEN
<form action="/auth/gen" method="POST">
USER <input type="text" name="user">
PASS <input type="password" name="password">
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

        if self.path == '/auth/gen':
            # Render out the login form
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(FORM, 'UTF-8'))
            return

        # Otherwise return 404
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == '/auth/gen':

            # Check the TOTP Secret
            params = self.parse_POST()
            SALTFILE = PATH + ".salt_" + params.get(b'user')[0].decode()
            PASSWORDFILE = PATH + ".password_" + params.get(b'user')[0].decode() + "_secret"
            SECFILE = PATH + '.totp_' + params.get(b'user')[0].decode() + '_secret' 

            SALT = open(SALTFILE, 'w+')
            logger.info("SALT FILE %s " % SALTFILE)
            SALTBASE64 = base64.b64encode(os.urandom(32)).decode('utf-8')
            SALT.write(SALTBASE64)
            SALT.close()
                
            logger.info("SALT OK")

            PASS = open(PASSWORDFILE, 'w+')
            logger.info("PASS presque OK")
            PASSWORDBASE64 = base64.b64encode(hashlib.pbkdf2_hmac('sha256',params.get(b'password')[0].decode().encode('utf-8'),base64.b64decode(SALTBASE64),10000)).decode('utf-8')
            PASS.write(PASSWORDBASE64)
            PASS.close()

            logger.info("PASS OK")

            SEC = open(SECFILE, 'w+')
            SECRET = pyotp.random_base32()  
            SEC.write(SECRET)
            SEC.close()
            
            logger.info("SEC OK")

            self.send_response(201)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            QR=pyqrcode.create(SECRET)
            PAGE="<img title='" + SECRET + "' style='display:block; width:500px;height:500px;' id='base64image' src='data:image/png;base64, " + QR.png_as_base64_str(scale=8) + "' /><br/> SECRET : " + SECRET 
            self.wfile.write(bytes(PAGE, 'UTF-8'))
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
