#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os

import webapp2
import jinja2
import re
import logging

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir=os.path.join(os.path.dirname(__file__), 'templates')
jinja_env= jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class Intermediat(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)
	def render_str(self,template,**params):
		t=jinja_env.get_template(template)
		return t.render(params)
	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

#Store the msg
class Message(db.Model):
	username = db.StringProperty(required=True)
	msg = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add = True)

#Store the user detail
class Accounts(db.Model):
	username = db.StringProperty(required=True)
	password = db.StringProperty(required=True)
	
import hmac

# Implement the hash_str function to use HMAC and our SECRET instead of md5

SECRET = ""
PSECRET = ""

# stores key values
class Keyss(db.Model):
	keyName = db.StringProperty(required=True)
	value = db.StringProperty(required=True)

def getSecretKeys():
	global SECRET 
	SECRET = db.GqlQuery("select value from Keyss where keyName=:1",'SECRET')
	SECRET = str(list(SECRET)[0].value).encode('utf-8')

def getPsecretKey():	
	global PSECRET
	PSECRET = db.GqlQuery("select value from Keyss where keyName=:1",'PSECRET')
	# print "PSECRET VALUE LOGGING: " + list(PSECRET)[0].value
	PSECRET = str(list(PSECRET)[0].value).encode('utf-8')

def hash_str(s):
	getSecretKeys()
	return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def hash_pass(s):
	getPsecretKey()
	return hmac.new(PSECRET,s).hexdigest()

def make_secure_password(s):
	return "%s" % (hash_pass(s))

def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

def getUsernameOnly(h):
	return h.split('|')[0]
	
#Caching msgs
def lastMessages(update=False):
	key = 'top'
	msgs = memcache.get(key)
	if update or msgs is None:
		logging.error('DB Query')
		msgs = db.GqlQuery("select * from Message order by created desc")
		msgs = list(msgs)
		for mg in msgs:
			logging.error(type(mg))
			logging.error('before decodeing')
			logging.error(mg.msg)
			mg.msg=hash_message(mg.msg)
			logging.error('after decodeing')
			logging.error(mg.msg)
		memcache.set(key,msgs)
	return msgs

# hash function for hashing message
def hash_message(message_text):
	hash_message=""
	for i in message_text:
		if i==' ':
			hash_message+=' '
		elif ord(i)>95:
			if (ord(i)+13)<122:
				hash_message+=chr((ord(i)+13))
			else:
				hash_message+=chr((ord(i)-97+13)%26+97)
		else:
			if (ord(i)+13)<92:
				hash_message+=chr((ord(i)+13))
			else:
				hash_message+=chr((ord(i)-65+13)%26+65)
	#print message_text
	#print hash_message
	return hash_message

#chat page
class FrontHandler(Intermediat):
	def render_front(self,msg="",error=""):
		msgs = db.GqlQuery("select * from Message order by created desc")
		username = self.request.get('username')
		lastMessages()
		if check_secure_val(username):
			username=getUsernameOnly(username)
			logging.error('in FrontHandler.render_front...')
			decode_messages = list()
			for mg in msgs:
				#logging.error(type(mg))
				logging.error('before decodeing')
				logging.error(mg.msg)
				mg.msg = hash_message(mg.msg)
				logging.error('after decodeing')
				logging.error(mg.msg)
				decode_messages.append(mg)
			for mg in decode_messages:
				logging.error(mg)
			self.render("front.html",username=username,msg=msg,msgs=decode_messages)
		else:
			username=getUsernameOnly(username)
			for mg in msgs:
				mg.msg=hash_message(mg.msg)
			self.render('front.html',username=username,msg=msg,msgs=msgs,error='Please donot interfere with the URL!!')
	
	def get(self):
		self.render_front()
		
	def post(self):
		msg=self.request.get("msg")
		username=self.request.get("username")
		if msg:
			a = Message(username=getUsernameOnly(username),msg=hash_message(msg))
			#a = Message(username=getUsernameOnly(username),msg=msg)
			a.put()
			lastMessages(True)
			self.redirect("/front.html?username="+username)
			self.render_front()
			self.render_front()
		else:
			error="require text in the box"
			self.render_front(msg,error)

#validation function
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

def valid_username(username):
    return username and USER_RE.match(username)

def username_exist(account):
    acc=account.get()
    if acc is not None:
		return False
    return True

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)
		
#login page handler
class LoginHandler(Intermediat):

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        password = make_secure_password(password)
        account = db.GqlQuery("SELECT * FROM Accounts WHERE username = :1 AND password = :2", username, password)
        #self.redirect("check.html",account)
        params = dict(username = username)
        have_error = False
        if username_exist(account) :
            params['error'] = "That's not a valid username and password combination."
            have_error = True
        #self.redirect('check.html', account)
        if have_error:
            self.render('login.html', **params)
        else:
			self.redirect('/front.html?username='+make_secure_val(username))  #username is hashed
			
#sigup page handler
class SigninHandler(Intermediat):

    def get(self):
        self.render("signin.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        acc = db.GqlQuery("SELECT * FROM Accounts WHERE username = :1", username)
        params = dict(username = username)
		
        if not username_exist(acc):
            params['error_username'] = "This username is already used."
            have_error = True
		
        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
			
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if have_error:
            self.render('signin.html', **params)
        else:
            a=Accounts(username=username,password=make_secure_password(password))
            a.put()
            self.redirect('/front.html?username='+make_secure_val(username))   #username is hashed
			
			
app = webapp2.WSGIApplication([
    ('/signin.html', SigninHandler),('/front.html',FrontHandler),('/',LoginHandler)
], debug=True)
