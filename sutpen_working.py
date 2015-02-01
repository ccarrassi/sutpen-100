import webapp2
import jinja2
import os
from google.appengine.ext import db
from utils import *
import logging

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = False)



def noAschii(s):
	return re.sub(r'\W+', '', s)

def tagify(s):
	"""Will take a str and return tagified version.
	e.g. pikachu sucks, mario's mayhem >>> ['pikachu sucks', 'marios mayhem']"""
	l = s.split(",")
	"""['pikachu sucks', ' mario's mayhem']"""

	l = [each.strip(" ") for each in l]
	"""['pikachu sucks', 'mario's mayhem']"""

	l = [each.split(" ") for each in l]
	"""[['pikachu', 'sucks'], ['mario's', 'mayhem']]"""

	l = [" ".join([noAschii(those) for those in each]) for each in l]
	"""['pikachu sucks', 'marios mayhem']"""

	return l
	# tag_list = ["-".join(each) for each in nest_l]
	# return tag_list

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)


class Entry(db.Model):
	title = db.StringProperty(required = True)
	author = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	location = db.StringProperty(required = True)
	tags = db.StringListProperty()
	category = db.StringProperty(required = True)



class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainPage(Handler):
	def render_page(self):
		page_number = self.request.get("p")
		tag = self.request.get("t")
		if page_number:
			offset_amount = str((int(page_number)-1) * 10)
			entries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10 OFFSET %s" % offset_amount)
		else:
			entries = db.GqlQuery("SELECT * FROM Entry ORDER BY created DESC LIMIT 10")


		self.render("front_content.html", entries=entries)

	def get(self):
		self.render_page()

class AddPost(Handler):
	def get(self):
		user = self.request.cookies.get('username')
		if not user:
			self.redirect('/login')
		else:
			self.render("addpost.html")

	def post(self):

		title = self.request.get("title")
		content = self.request.get("content")
		location = self.request.get("location")
		tags = self.request.get("tags")
		author = self.request.cookies.get('username').split("|")[0]
		title_list = title.split(" ")
		key_list = [noAschii(each) for each in title_list]
		key = "_".join(key_list)
		category = self.request.get("category")

		if title and content and location:
			if tags:
				# new_tag_list = tags.split(",")
				# tags = [each.strip(" ") for each in new_tag_list]
				tags = tagify(tags)
			else:
				tags = []
			new_entry = Entry(key_name=key, title=title, content=content, location=location, tags=tags, author=author, category=category)
			submission = new_entry.put()
			self.redirect("/%s" % key)
		else:
			error = "You must include a title, content and a location to submit."
			self.render("addpost.html", title=title, content=content, location=location, tags=tags, error=error)

class EditPost(Handler):
	def get(self, key):
		user = self.request.cookies.get('username')
		if not user:
			self.redirect('/login')
		else:
			post = Entry.get_by_key_name(key)
			title = post.title
			content = post.content
			location = post.location
			tag_list = post.tags
			tags = ", ".join(tag_list)

			self.render("addpost.html", title=title, content=content, location=location, tags=tags)

	def post(self, key):
		title = self.request.get("title")
		content = self.request.get("content")
		location = self.request.get("location")
		p_tags = self.request.get("tags")

		if title and content and location:
			if p_tags:
				tags = tagify(p_tags)
				# new_tag_list = p_tags.split(",")
				# tags = [each.strip(" ") for each in new_tag_list]
			else:
				tags = []
			revise_entry = Entry(key_name=key, title=title,content=content,location=location,tags=tags)
			submission = revise_entry.put()
			self.redirect("/%s" % key)
		else:
			error = "You must include a title, content and a location to edit."
			self.render("addpost.html", title=title, content=content, location=location, tags=tags, error=error)

class Post(Handler):
	def get (self, key):
		post = Entry.get_by_key_name(key)
		title = post.title
		content = post.content
		location = post.location
		key = post.key().name()
		# tags = post.tags
		#e_id = post.key().id()
		date = "%s/%s/%s" % (post.created.month, post.created.day, post.created.year)
		self.render("post.html", title=title, content=content, location=location, date=date, key=key)

class UserPage(Handler):
	def get(self):
		pass

class Login(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		user_name = self.request.get('username')
		user_pass = self.request.get('password')

		q = db.GqlQuery("SELECT * FROM User")
		l = {str(each.username): st(each.password) for each in q}

		if user_name in l.keys() and l[user_name] == user_pass:
			hashed_user_name = make_secure_val(str(user_name))
			self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % hashed_user_name)
			self.redirect("/")
		else:
			user_error = "Invalid login."
			self.render("login.html", user_error)

class Logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
		self.redirect('/')

class SignUp(Handler):
	def get(self):
		self.render("users.html")

	def post(self):
		# self.response.headers['Content-Type'] = 'text/plain'
		user_name = str(self.request.get('username'))
		user_pass = str(self.request.get('password'))
		user_display = str(self.request.get('display'))
		user_verify = self.request.get('verify')

		valid_user = valid_username(user_name)
		valid_display = valid_username(user_display)
		valid_pass = valid_password(user_pass)
		valid_ver = valid_verify(user_pass, user_verify)
		user_lookup = User.get_by_key_name(user_name)

		user_error = ""
		pass_error = ""
		ver_error = ""
		disp_error = ""

		valid = True
		passcheck = True

		if not valid_user:
			valid = False
			user_error = "That is not a valid username."

		if not valid_display:
			valid = False
			disp_error = "That is not a valid display name."

		if user_lookup:
			valid = False
			user_error = "That username already exists!"

		if not valid_pass:
			valid = False
			passcheck = False
			pass_error = "That is not a valid password."

		if not valid_ver:
			if passcheck:
				valid = False
				verify_error = "Those passwords do not match."

		if valid == True:
			hashed_user_name = make_secure_val(user_name)
			self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % hashed_user_name)
			user = User(username=user_name, password = user_pass, displayName = user_display)
			user.put()
			self.redirect('/')
		else:
			self.render("users.html", username=user_name, user_error=user_error, pass_error=pass_error, ver_error=ver_error)

class TagPage(Handler):
	def get(self, tag):
		tag = " ".join(tag[1:].split("_"))
		page_number = self.request.get("p")
		if page_number:
			offset_amount = str((int(page_number)-1) * 10)
			entries = db.GqlQuery("SELECT * FROM Entry WHERE tags = '%s' ORDER BY created DESC LIMIT 10 OFFSET %s" % (offset_amount, tag))
		else:
			entries = db.GqlQuery("SELECT * FROM Entry WHERE tags = '%s' ORDER BY created DESC LIMIT 10" % tag)

		self.render("front_content.html", entries=entries)

class Production(Handler):
	def get(self):
		pull = db.GqlQuery("SELECT * FROM Entry")
		yank = db.GqlQuery("SELECT * FROM User")
		both = []

		for each in pull:
			both.append(each.title)

		for each in yank:
			both.append(each.username)



		self.write(pull[0].title)
		self.write(yank[0].username)
		self.write(both)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

application = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/new', AddPost),
    ('/edit' + r'/(\w+)', EditPost),
    ('/login', Login),
    ('/logout', Logout),
    ('/signup', SignUp),
    ('/user' + PAGE_RE, UserPage),
    ('/_prod', Production),
    (r'/(\w+)', Post),
    ('/tag' + PAGE_RE, TagPage)
], debug=True)