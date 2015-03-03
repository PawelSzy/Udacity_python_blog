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
from google.appengine.ext import db
import json
import hashlib
from google.appengine.api import memcache
import datetime 
import re

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

LAST_QUERY = datetime.datetime.now()
UPDATE_TIME =(LAST_QUERY-LAST_QUERY).total_seconds()

page = """
<!DOCTYPE html>

<html>
  <head>
    <title>Sign Up Page</title>
  </head>

  <body>
    <h2>Enter data to Sing Up:</h2>
    <form method="post">
   <label>
        <input type="text" name="username" value="">
    username <div style="color: red">%(username)s</div>
    <div style="color: red">%(username_exist)s</div>
    </label>
    </br>
    <label>
        <input type="password" name="password">
        password <div style="color: red">%(password)s</div>
    </label>
    </br>
    <label>
        <input type="password" name="verify">
        verify password <div style="color: red">%(verify_password)s</div>
    </label>
    </br>
       <label>
        <input type="text" name="email">
        Email <div style="color: red">%(email)s</div>
    </label>
    </br>
    <input type="submit">
    </form>
  </body>

</html>
"""

login_page ="""
<!DOCTYPE html>

<html>
  <head>
    <title>Sign Up Page</title>
  </head>

  <body>
    <h2>Enter data to Login:</h2>
    <form method="post">
   <label>
        <input type="text" name="username" value="">
    username <div style="color: red">%(username)s</div>
    </label>
    </br>
    <label>
        <input type="password" name="password">
        password <div style="color: red">%(password)s</div>
    </label>
    </br>
    <input type="submit">
    </form>
  </body>

</html>
"""

def hash_str(s):
        return hashlib.md5(s).hexdigest()

def make_secure_val(s):
        return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
        val = h.split('|')[0]
        if h == make_secure_val(val):
                return val
        else:
            return False


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    
class UsersBase(db.Model):
    username = db.StringProperty(required = True)
    password = db.TextProperty(required = True)
    email = db.TextProperty()
    

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)     

def get_posts(update = False):
        key ='top'
        posts = memcache.get(key)
        if posts is None or update:
            posts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 10")
            LAST_QUERY = datetime.datetime.now()
        posts=list(posts)
        memcache.set(key, posts)
        return posts
    
class MainPage(Handler):   #class MainPage(webapp2.RequestHandler)
    def render_front(self, subject="", content="", error=""):
        global UPDATE_TIME
        posts =get_posts()
        self.render("stronka.html", posts=posts, error=error, UPDATE_TIME=UPDATE_TIME)
    def get(self):
        self.render_front()

        
    def write_form(self, error="", username="", password="", verify="", email=""):
        error_lib = {"username": "", "password": "", "verify_password": "", "email": ""}
        if not username:
            error_lib["username"]="Wrong Username"
        if not password:
            error_lib["password"]="Wrong password"
        if not verify:
            error_lib["verify_password"] = "password and verify password don't match"
        if not email:
            error_lib["email"]="Wrong email"
        
        self.response.out.write(page %{"username": error_lib["username"], "password": error_lib["password"],
                                                    "verify_password": error_lib["verify_password"], "email": error_lib["email"]})
        
    def post(self): 

        subject = self.request.get("subject")
        content = self.request.get("content")
        
        if subject and content:
            #a = Blog(parent = blog_key(), subject = subject, content = content)
            #a.put()
            self.redirect("/newpost")
            #self.redirect('/%s' % str(a.key().id()))
            #self.redirect('/blog/%s/%s' % (id, subject))
        else:
            error = "Please we need both subject and content!"
            self.render_front(subject, content, error)
        
class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        cookie = self.request.cookies.get('username')
        if cookie:
            name = check_secure_val(cookie)
            if name!=False:
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.out.write("Welcome: " + name +" !")
            else:
                self.redirect("/signup")
                #self.write_form(True, True, True, True, True, True )
        else:
            self.redirect("/signup")

class NewPostHandler(Handler):
    #def get(self):
        #posts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 1")
        #self.render("newpost.html", posts=posts[:1])
        
    def get(self):
        self.render("newpost.html")

    def post(self):
        global UPDATE_TIME
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Blog(parent = blog_key(), subject = subject, content = content)
            p.put()
            get_posts(True) #clear memcache
            ACTUAL_TIME = datetime.datetime.now()
            UPDATE_TIME=(ACTUAL_TIME-LAST_QUERY).total_seconds()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)        
 
class PostHandler(Handler):
    def get(self, post_id):
        global UPDATE_TIME
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = memcache.get(str(key))
        if post is None:
            post = db.get(key)
            if not post:
                self.error(404)
                return
        #post=list(post)
        memcache.set(str(key), post) 
        time_now = datetime.datetime.now() 
        
        if UPDATE_TIME == '0':
            update_time = '0'
        else:    
            update_time=(time_now-post.created).total_seconds()
        self.render("permalink.html", posts = [post], UPDATE_TIME=update_time)
        
class LoginHandler(webapp2.RequestHandler):
    def get(self):
        self.write_form(True, True, True)
        
        
    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def valid_password(self, password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return PASS_RE.match(password)        
    
    def write_form(self, error="", username="", password=""):
        error_lib = {"username": "", "password": "", "verify_password": ""}
        if not username:
            error_lib["username"]="Wrong Username"
        if not password:
            error_lib["password"]="Wrong password"
        self.response.out.write(login_page %{"username": error_lib["username"], "password": error_lib["password"]})    
            
    def post(self):
        user_username = self.request.get("username")
        user_password = self.request.get("password")
        
        username = self.valid_username(user_username)
        password = self.valid_password(user_password)
        
        if not(username and password):
            self.write_form("Change", username, password)
        else:
            users = db.GqlQuery("SELECT * FROM UsersBase")
            for user in users:
                self.response.out.write(user)
                if user.username==user_username:
                    if user.password==user_password:
                        self.redirect("/welcome")
                    else:
                        self.write_form(error="", username=user_username, password=False)
            self.write_form(error="", password="", username=False)  

class logoutHandler(webapp2.RequestHandler):
    def get(self):
        cookie = self.request.cookies.get('username')
        name = check_secure_val(cookie)
        # self.response.delete_cookie('username'==name)
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect("/signup")        
        
class signupHandler(webapp2.RequestHandler):  
    def get(self):
        self.write_form(True, True, True, True, True, True )

    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def valid_password(self, password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return PASS_RE.match(password)    
    
    def valid_verify_password(self, password, verify):
        return password == verify
        
    def valid_email(self, email):
        if email=="":
            return True
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        return EMAIL_RE.match(email)        
        
        
    def write_form(self, error="", username="", password="", verify="", email="", username_exist=""):
        error_lib = {"username": "", "password": "", "verify_password": "", "email": "", "username_exist": ""}
        if not username:
            error_lib["username"]="Wrong Username"
        if not password:
            error_lib["password"]="Wrong password"
        if not verify:
            error_lib["verify_password"] = "password and verify password don't match"
        if not email:
            error_lib["email"]="Wrong email"
        if username_exist==True:
            error_lib["username_exist"]="User witch that name exist"
        
        self.response.out.write(page %{"username": error_lib["username"], "password": error_lib["password"],
                                                    "verify_password": error_lib["verify_password"], "email": error_lib["email"], "username_exist": error_lib["username_exist"]})
        
    def post(self):
        user_username = self.request.get("username")
        user_password = self.request.get("password")
        user_verify = self.request.get("verify")
        user_email = self.request.get("email")
        

        username = self.valid_username(user_username)
        password = self.valid_password(user_password)
        verify = self.valid_verify_password(user_password, user_verify)
        email = self.valid_email(user_email)
        
        cookie = self.request.cookies.get('username')
        if not cookie:
            username_exist = False
        else:
            name = check_secure_val(cookie)
            if name == user_username:
                username_exist = True
            else:
                username_exist = False
        

        if not(username and password and verify and email and not username_exist):
            self.write_form("Change", username, password, verify, email, username_exist)
        else:
            if email:
                a = UsersBase(username = user_username, password = user_password, email=user_email)
            else:  
                a = UsersBase(username = user_username, password = user_password)
            a.put()
            hashUsername = make_secure_val(str(user_username))
            #self.response.headers.add_header('Set-Cookie', 'visits=%s' % new_cookie_val)
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % hashUsername)
            self.redirect("/welcome")        
        
class JsonHandlerMainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC LIMIT 10")
        Jpost=""
        for post in posts:
            Jpost+=", "+json.dumps({'subject': post.subject, 'content': post.content})
        self.response.headers['Content-Typr'] ='application/json; charset=UTF-8'
        self.response.out.write(Jpost)
class JsonHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        
        Jpost.json.dumps({'subject': post.subject, 'content': post.content})
        self.response.out.write(Jpost)    
        #self.render("permalink.html", posts = [post])
        
class flushHandler(Handler):
    def get(self):
        global UPDATE_TIME
        memcache.flush_all()
        UPDATE_TIME = '0'
        self.redirect('/')
        

app = webapp2.WSGIApplication([('/', MainPage),('/newpost', NewPostHandler), ('/signup', signupHandler), 
                                    ('/welcome', WelcomeHandler),('/login', LoginHandler),('/logout', logoutHandler), ('/flush', flushHandler),
                                    ('/.json', JsonHandlerMainPage), ('/([0-9]+)/.json', JsonHandler), ('/([0-9]+)', PostHandler)],debug=True)        