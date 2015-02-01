import hashlib
import hmac
import re

SECRET = "phgosgowoughwojw"

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split("|")[0] 
	if h == make_secure_val(val):
		return val

def valid_verify(password, verify):
    if password == verify:
        return password

def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return PASS_RE.match(password)

def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)

def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    return EMAIL_RE.match(email)

# def login_check():
# 	username_cookie = self.request.cookies.get('username').split("|")[0]
# 	if not username_cookie:
# 		return username_cookie
# 	else:
# 		return True