import http.cookies
import http.server
import socketserver
import random
import time
from urllib.parse import parse_qs
from cgi import parse_header, parse_multipart
import hashlib
import os
import json

import gnupg 
import pyqrcode
import qrtools
import datetime

import base64
import pyotp
"""https://github.com/pyauth/pyotp/blob/develop/src/pyotp/totp.py"""

import logging


logger = logging.getLogger('simpleOTP')
logger.setLevel(logging.DEBUG)

# Setup gnupg
gpg = gnupg.GPG(gnupghome='/home/.gnupg')
gpgrecipient = 'key@local'
gpgkeypass = "None"

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
<title>Totp Agent</title>
</head>
<body>
<div style="background-color: #333;width: auto;height: auto;position: absolute;top: 0px;left: 0px;">
<div style="background-color: #09F;color: white;font-size: 4em;font-style: italic;font-family: 'Open Sans';padding:0em;/* position: absolute; */top: 0px;left: 0px;width:98%;box-shadow: 2px 2px 3px #333;padding: 1%;" >
TOTP AGENT
</div>
<div style="background-color: #333; font-size: 3em;color: white;margin-top: 1em;margin-left: 1em;">
<form action="/auth/add" method="POST" enctype="multipart/form-data">
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;">
Title <input type="text" name="title">
</div>
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;">
Secret <input type="text" name="secret">
</div>
<div style="background-color: #333; font-size: 0.8em;color: white;margin-top: 1em;margin-left: 2em;">
Options [Optionals] defaults : (digits=6,digest=None,name=None,issuer=None,interval=30) <input type="text" name="options" size=100>
</div>
<br/>
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;">
Or use QRCODE : 
<input type="file" id="qrcode" name="qrcode" accept="image/png, image/jpeg" /><br/>
</div>
<div style="background-color: #333; font-size: 1em;color: white;margin-top: 1em;margin-left: 2em;padding-left: 3em;">
Submit :  
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
<br/><a href="/auth/list" title="list" style="box-shadow:inset 0px 1px 0px 0px #ffffff
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
	text-shadow:0px 1px 0px #ffffff;">list</a>
<br/><br/><a href="/auth/add" title="list" style="box-shadow:inset 0px 1px 0px 0px #ffffff
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
	text-shadow:0px 1px 0px #ffffff;">add</a>
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
        if self.path == '/auth/otpgen.js':
            # Render out js
            logger.info("GET otpgen.js")
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            js = open("otpgen.js", "r")
            self.wfile.write(bytes(js.read(), 'UTF-8'))
            js.close()
            return 

        if self.path == '/auth/add':
            # Render out the login form
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(bytes(FORM, 'UTF-8'))
            return

        if self.path == '/auth/list':
            # Render out the login form
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            FILES = [f for f in os.listdir(PATH) if os.path.isfile(os.path.join(PATH, f))]
            TOTPSECRETS = [f for f in FILES if '_secret' in f ]
            SUFTITLES = [f.replace(".totp_", "") for f in TOTPSECRETS]
            TITLES = [f.replace("_secret", "") for f in SUFTITLES]
            LIST="""
<html>
<head>
<title>Totp Agent</title>
</head>
<body>
<div style="background-color: #333;width: 100%;height: auto;position: absolute;top: 0px;left: 0px;">
<div style="background-color: #09F;color: white;font-size: 4em;font-style: italic;font-family: 'Open Sans';padding:0;/* position: absolute; */top: 0px;left: 0px;width:98%;box-shadow: 2px 2px 3px #333;padding: 1%;" >
TOTP AGENT
</div>
<br/>
<div>
<a href="/auth/add" title="add"  style="box-shadow:inset 0px 1px 0px 0px #ffffff; 
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
	text-shadow:0px 1px 0px #ffffff;">Add entry</a>
<form id="setkeypass" action="" method="">
<div style="background-color: #333; font-size: 1.5em;color: white;margin-top: 1em;margin-left: 2em;">
GPG Passphrase :<input type="password" name="secretpass">
</div>
<br/>
<button class="btn-submit" type="button" id="setkeypassbtn" style="box-shadow:inset 0px 1px 0px 0px #ffffff;
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
	text-shadow:0px 1px 0px #ffffff;">Set pass</button>
</form>
</div>
<br/>
<form id="sampleForm" action="" method="">
<div style="background-color: #333; font-size: 1.5em;color: white;margin-top: 1em;margin-left: 2em;">
""" + self.printlist(TITLES) + """
</div>
</form>
<script src="otpgen.js"></script>
<br/><a href="/auth/list" title="list" style="box-shadow:inset 0px 1px 0px 0px #ffffff
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
	text-shadow:0px 1px 0px #ffffff;">list</a>
<br/><br/><a href="/auth/add" title="list" style="box-shadow:inset 0px 1px 0px 0px #ffffff
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
	text-shadow:0px 1px 0px #ffffff;">add</a>
</body>
</html>"""
            self.wfile.write(bytes(LIST, 'UTF-8'))
            return

        # Otherwise return 404
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path == '/auth/add':

            # Check the TOTP Secret
            params = self.parse_POST()
            #logger.info("params %s", params)
            if params.get('secret')[0] == '':
               if params.get('qrcode')[0] == '':
                 self.send_response(302)
                 self.send_header('Location', '/auth/add')
                 self.end_headers()
                 logger.info("No secret or qrcode")
                 return
               else:
                 #logger.info("qrcode %s", params.get('qrcode')[0])
                 SECFILEQR = PATH + '.totp_' + params.get('title')[0] + '_QR.png' 
                 SECQR = open(SECFILEQR, 'wb')
                 SECQR.write(str(gpg.encrypt(params.get('qrcode')[0],gpgrecipient,always_trust="true")))
                 SECQR.close()
                 logger.info("SECQR OK")
                 
                 qr = qrtools.QR(filename=SECFILEQR)
                 qr.decode()
                 #logger.info("qrcode %s", qr.data)


            SECFILE = PATH + '.totp_' + params.get('title')[0] + '_secret' 

            SEC = open(SECFILE, 'w+')
            
            if 'qr' in locals():
              SECRET=qr.data 
            else:
              SECRET = params.get('secret')[0]
            #logger.info("secret %s", SECRET)

            SEC.write(str(gpg.encrypt(SECRET,gpgrecipient)))
            SEC.close()
            if params.get('options')[0] != '':
              OPTFILE = PATH + '.totp_' + params.get('title')[0] + '_options' 
              OPT=open(OPTFILE, 'w+')
              OPT.write(params.get('options')[0])
              OPT.close()
            
            logger.info("OTP SECRET SAVE OK %s", params.get('title')[0])

            self.send_response(201)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            QR=pyqrcode.create(SECRET)
            PAGE="""
            <div style="background-color: #333;width: 100%;height: 100%;position: absolute;top: 0px;left: 0px;">
            <div style="background-color: #09F;color: white;font-size: 4em;font-style: italic;font-family: 'Open Sans';padding:0,75em;/* position: absolute; */top: 0px;left: 0px;width:100%;box-shadow: 2px 2px 3px #333;padding: 0.35em;" >
            OTP SAVED FOR : '""" + params.get('title')[0] + """'</div><br/><img title='""" + params.get('title')[0] + """' style='display:block; width:500px;height:500px;' id='base64image' src='data:image/png;base64, """ + QR.png_as_base64_str(scale=8) + """' /><br/>
            <br/><a href="/auth/list" title="list" style="box-shadow:inset 0px 1px 0px 0px #ffffff
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
            	text-shadow:0px 1px 0px #ffffff;">list</a>
            <br/><br/><a href="/auth/add" title="list" style="box-shadow:inset 0px 1px 0px 0px #ffffff
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
            	text-shadow:0px 1px 0px #ffffff;">add</a>
            """
            self.wfile.write(bytes(PAGE, 'UTF-8'))
            return
        
        if self.path == '/totpgpgkey':
            logger.info("totpgpgkey")
            params = self.parse_POST()
            #logger.info(params)
            try:
                #logger.info(params.decode())
                parameters = json.loads(params.decode())
                #logger.info(parameters)
                #logger.info(parameters["file"])
                global gpgkeypass
                gpgkeypass=parameters["secretpass"]
                #logger.info(gpgkeypass)
                self.send_response(202)
                self.end_headers()
                return
            except FileNotFoundError:
                #logger.info(params)
                self.send_response(302)
                self.send_header('Location', "/auth/list")
                self.end_headers()
                return
        
        if self.path == '/totpgen':
            logger.info("totpgen")
            params = self.parse_POST()
            #logger.info(gpgkeypass)
            if gpgkeypass == 'None':
                logger.info("No gpgpass provided")
                self.send_response(302)
                self.send_header('Location', "/auth/list")
                self.end_headers()
                return
            try:
                #logger.info(params.decode())
                parameters = json.loads(params.decode())
                #logger.info(parameters)
                #logger.info(parameters["file"])
                SECRET_GPG = open(PATH + '.totp_' + parameters["file"] + '_secret').read().strip()
                #logger.info(SECRET_GPG)
                SECRET = gpg.decrypt(SECRET_GPG,passphrase=gpgkeypass)
                #logger.info(SECRET)
            except FileNotFoundError:
                self.send_response(302)
                self.send_header('Location', "/auth/list")
                self.end_headers()
                return
            except Exception as err:
                logger.info(err)
            if os.path.isfile(PATH + '.totp_' + parameters["file"] + '_options'):
                OPTIONS = open(PATH + '.totp_' + parameters["file"] + '_options').read().strip()
                logger.info("options")
                opts = {}
                for o in OPTIONS.split(","):
                  var, val = o.split("=")
                  opts[var] = val
                if "digits" in opts:  
                  digits=int(opts["digits"])
                else:
                  digits=6
                if "digest" in opts:  
                  if opts["digest"]!="None":
                    digest=opts["digest"]
                  else:
                    digest=None
                else:
                  digest=None
                if "issuer" in opts:  
                  issuer=opts["issuer"]
                else:
                  issuer=None
                if "name" in opts:  
                  name=opts["name"]
                else:
                  name=None
                if "interval" in opts:  
                  interval=int(opts["interval"])
                else:
                  interval=30
                #logger.info(SECRET)
                #logger.info("digits=" + str(digits)+ ", digest="+str(digest)+", name="+str(name)+", issuer="+str(issuer)+", interval="+str(interval)+"")
                totp = pyotp.TOTP(str(SECRET), digits=digits, digest=digest, name=name, issuer=issuer, interval=interval)
            else:
                totp = pyotp.TOTP(str(SECRET))
            if SECRET.ok == False:
                logger.info("Wrong passkey or unable to decrypt")
                self.send_response(302)
                self.send_header('Location', "/auth/list")
                self.end_headers()
                return
            #TOKEN = {"token": bytes(pyotp.TOTP(SECRET).now(), 'UTF-8')}
            left = totp.interval - datetime.datetime.now().timestamp() % totp.interval
            TOKEN = {"token": totp.now(), "timeleft": left}
            #logger.info(TOKEN)
            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(bytes(str(TOKEN) ,'UTF-8'))))
            self.end_headers()
            #logger.info(dir(self))
            self.wfile.write(bytes(str(TOKEN),'UTF-8'))
            return 
                
        # Otherwise return 404
        self.send_response(404)
        self.end_headers()

    def printlist(self, TITLES):
        """List files in totp"""
        #logger.info("List %s", TITLES)
        TEXT=""
        LOOP=1
        for f in TITLES:
          TEXT=TEXT + """
<div id="name_""" + str(LOOP) + """" order='""" + str(LOOP) + """' name="title_otp" file='""" + f + """' value='""" + f + """'>OTP : <b>""" + f + """</b></div>
<br/>
Value <input type="text" otp='Value_""" + str(LOOP) + """' file='""" + f + """' order='""" + str(LOOP) + """' id="Value_""" + str(LOOP) + """" name="Value_""" + str(LOOP) + """" value="">
Time <input type="text" time='Time_""" + str(LOOP) + """' file='""" + f + """' order='""" + str(LOOP) + """' id="Time_""" + str(LOOP) + """" name="Time_""" + str(LOOP) + """" value="">
<button class="btn-submit" file='""" + f + """' order='""" + str(LOOP) + """' type="button" id="btnSubmit_""" + str(LOOP) + """" value="btnSubmit_""" + str(LOOP) + """">Reveal</button>
<br/>   
<br/>"""
          #logger.info("TEXT %s", TEXT)
          LOOP+=1
        TEXT=TEXT + """<div id=LOOP value='""" + str(LOOP) + """'></div>"""

        return TEXT


    def parse_POST(self):
        """Lifted from https://stackoverflow.com/questions/4233218/"""
        ctype, pdict = parse_header(self.headers['content-type'])
        #logger.info("type %s, p  %s", ctype, pdict)
        if ctype == 'multipart/form-data' :
            content_len = int(self.headers.get('Content-length'))
            pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
            pdict['CONTENT-LENGTH'] = content_len
            postvars = parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['Content-Length'])
            postvars = parse_qs(self.rfile.read(length), keep_blank_values=1)
        elif ctype == 'application/json':
            length = int(self.headers['Content-Length'])
            #logger.info("params  %s", self.rfile.read(length))
            #logger.info("params  %s s", self.rfile.read(length))
            postvars = self.rfile.read(length)
            #logger.info("params  %s", postvars)
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
