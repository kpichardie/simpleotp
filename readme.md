# Basic TOTP Manager for `auth_request` Server nginx and otp agent alternative to authy

## What is this for?

Have you ever wanted to add more security to a web application without modifying the web application itself? Take for example Jupter Notebook/Lab, which allows you to run arbitrary code from a web browser. It supports a built-in password / token-based authentication. Hopefully you're using a unique password, but if you're following proper security practices it's generally a good idea to protect stuff with "something you know and something you have." Chances are that if you've gotten this far you don't need me to convince you of the merits of two factor authentication.

Agent is used as a replacement of Authy desktop that will no longer be supported. Agent is based on otp and gpg to ensure security.  

## How does it work?

### Nginx
I use nginx in front of a variety of web services to handle SSL termination (using letsencrypt, which is amazing and you should also use). Nginx has a handy module called auth_request that you can use to specify an endpoint to check if a user is authenticated. If the endpoint returns 200, the parent request is allowed to succeed, otherwise a 401 error is returned. You can set up nginx to then redirect the user to a login page where they can do whatever they need to assert proof of identity.

In this case, the auth endpoint is reverse proxied to the simple script in this repo, which does things like token checking and presenting a login form.

### Agent

Agent goal is to be able to store secrets MFA otp and generate otp codes. Two modes are available, web and cli. First generate gpgkey to encrypt/decrypt secrets. 

_Configuration :_
gpgrecipient = 'mygpgkey@local'

_Available Commands :_ 
 - get 
 - list
 - add 

```
# Start web 
sudo -s docker-compose up simpleotp-3

# Run list in cli
sudo -s docker-compose run simpleotp-3 python3 main-cli.py --command list 

# Run get in cli 
sudo -s docker-compose run simpleotp-3 python3 main-cli.py --command get --name otpname

# Help
usage: main-cli.py [-h] [--command command] [--name name] [--options options]

Cli for totp agent

optional arguments:
  -h, --help         show this help message and exit
  --command command  Available cli commands (list, get, add)
  --name name        Name of the otp
  --options options  Options for add otp default="digits=6,digest=None,name=None,issuer=None,interval=30"
```

## Example Configuration nginx

In something like `/etc/nginx/sites-enabled/default`

```
server {
        server_name jupyter.example.com;

        location /auth {
                proxy_pass http://127.0.0.1:8000; # This is the TOTP Server
                proxy_set_header X-Original-URI $request_uri;
        }

        # This ensures that if the TOTP server returns 401 we redirect to login
        error_page 401 = @error401;
        location @error401 {
            return 302 /auth/login;
        }

        location / {
                auth_request /auth/check;
                proxy_pass http://127.0.0.1:8888; # This is Jupyter

                # This is needed for Jupyter to proxy websockets correctly, 
                # it's unrelated to auth but handy to have written down here 
                # for reference anyhow...
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection $connection_upgrade;
        }

# The rest of the server definition, including SSL and whatnot
```

## Additional assembly required Nginx:

1. You need to run `main.py` with Python3.5+ in a tmux session or something like supervisord.
2. You should generate a TOTP secret (i.e. `import pyotp; print(pyotp.random_base32())`) and store it in `.totp_secret` alongside `main.py` and also your two factor auth manager of choice (Google Authenticator, Duo, etc.)
```
python3 -c "import pyotp; print(pyotp.random_base32())" > .totp_secret
```
## Configuration for Nginx access

COOKIEARREA has 3 modes possible : 

 * Default mode with value `currentdomain` : Allow Cookie only for current website
 * Mode SSO defined with value `mydomain.fr` : Allow Cookie for the whole domain and subdomains
 * Mode SSO origin with value `origindomain` : Allow Cookie to be set to current origin. If I login on test.mydomain.fr, token will be for *.mydomain.fr. Then if I login to test.mydomain2.fr then a new token will be set for *.mydomain2.fr no matter which domain I use.

## FAQ

**Wait, this checks the TOTP secret before you enter a password?**

Yep, it feels kinda backwards, but I only have one login anyhow and I've rate-limited TOTP checks, so you can't hammer auth to figure out the TOTP secret.

**What about CSRF attacks?**

In my case Jupyter already prevents CSRF attacks and the only thing you could do (as far as I can tell) with CSRF attacks on the auth server is log a user out, so I haven't bothered.

