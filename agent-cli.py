import random
import time
import os
import json

import getpass
import argparse

import gnupg 
import pyqrcode
import qrtools
import datetime

import base64
import pyotp
"""https://github.com/pyauth/pyotp/blob/develop/src/pyotp/totp.py"""


# Setup gnupg
gpg = gnupg.GPG(gnupghome='/home/.gnupg')
gpgrecipient = 'key@local'

PATH = "/totp/"
TOKEN_LIFETIME = 60 * 60 * 24


def collect_args():
    parser = argparse.ArgumentParser(
        description='Cli for totp agent')
    parser.add_argument('--command', metavar='command', type=str,
                        default='list',
                        help='Available cli commands (list, get, add)')
    parser.add_argument('--name', metavar='name', type=str,
                        default=None,
                        help='Name of the otp')
    parser.add_argument('--options', metavar='options', type=str,
                        default="digits=6,digest=None,name=None,issuer=None,interval=30",
                        help='Options for add otp default="digits=6,digest=None,name=None,issuer=None,interval=30"')
    parser.add_argument('--mode', metavar='mode', type=str,
                        default="json",
                        help='Print mode "raw" or "json"')
    return parser


def list(): 
  FILES = [f for f in os.listdir(PATH) if os.path.isfile(os.path.join(PATH, f))]
  TOTPSECRETS = [f for f in FILES if '_secret' in f ]
  SUFTITLES = [f.replace(".totp_", "") for f in TOTPSECRETS]
  TITLES = [f.replace("_secret", "") for f in SUFTITLES]
  print(TITLES)

def get(args): 
  passphrase = getpass.getpass('GPG-Passphrase:') 
  try:
     SECRET_GPG = open(PATH + '.totp_' + args.name + '_secret').read().strip()
     SECRET = gpg.decrypt(SECRET_GPG,passphrase=passphrase)
  except FileNotFoundError:
      print("OTP not found")
      return
  except Exception as err:
      print(err)
      return
  if os.path.isfile(PATH + '.totp_' + args.name + '_options'):
      OPTIONS = open(PATH + '.totp_' + args.name + '_options').read().strip()
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
      totp = pyotp.TOTP(str(SECRET), digits=digits, digest=digest, name=name, issuer=issuer, interval=interval)
  else:
      totp = pyotp.TOTP(str(SECRET))
  if SECRET.ok == False:
      print("Wrong passkey or unable to decrypt")
      return
  left = totp.interval - datetime.datetime.now().timestamp() % totp.interval
  TEMP_TOTP = open(PATH + '.totp_secret_totplast',"w")
  TOKEN_TOTP=totp.now()
  TEMP_TOTP.write(TOKEN_TOTP)
  print("Saved to clipboard")
  if "mode" in args:
    if args.mode == "raw":
      TOKEN=TOKEN_TOTP 
    else:
      TOKEN = {"token": TOKEN_TOTP, "timeleft": left}
  print(TOKEN)
  return 

def add(): 
  #print("not handle yet")
  #return 
  
  mode = getpass.getpass('Which mode you want add "qrcode" or "secret"')
  
  if mode == "secret":
    secret = getpass.getpass('Secret:') 
  elif mode == "qrcode":
    qrcode = getpass.getpass('Imageqrcodepath:') 
     
    try: 
      qr = qrtools.QR(filename=qrcode)
      qr.decode()
    except Exception as err:
      print("error on qrcode %s", err)
  else:
    print("wrong mode should be 'secret' or 'qrcode'")
    return

  SECFILE = PATH + '.totp_' + args.name + '_secret' 
  SEC = open(SECFILE, 'w+')
  
  if mode == "secret":
    SECRET = secret
  elif mode == "qrcode":
    SECRET=qr.data 

  
  SEC.write(str(gpg.encrypt(SECRET,gpgrecipient,always_trust="true")))
  SEC.close()
  if args.options != '':
    OPTFILE = PATH + '.totp_' + args.name + '_options' 
    OPT=open(OPTFILE, 'w+')
    OPT.write(args.options)
    OPT.close()
  
  print("OTP SECRET SAVE OK %s", args.name)

if __name__ == '__main__':
    args = collect_args().parse_args()
    if args.command == "list":
       list()
    if args.command == "add":
       add()
    if args.command == "get":
       get(args)
