import webapp2
import jinja2
import os
from google.appengine.ext import db
from google.appengine.ext.db import polymodel
from utils import *
import logging
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = False)



def noAschii(s):
	"""Replaces any non-aschii characters from string s"""
	return re.sub(r'\W+', '', s)

def tagify(s):
	"""Will take a str and return tagified version."""

	#e.g. pikachu sucks, mario's mayhem >>> ['pikachu sucks', 'marios mayhem']
	l = s.split(",")
	#['pikachu sucks', ' mario's mayhem']

	l = [each.strip(" ") for each in l]
	#['pikachu sucks', 'mario's mayhem']

	l = [each.split(" ") for each in l]
	#[['pikachu', 'sucks'], ['mario's', 'mayhem']]

	l = [" ".join([noAschii(those) for those in each]) for each in l]
	#['pikachu sucks', 'marios mayhem']

	return l
	# tag_list = ["-".join(each) for each in nest_l]
	# return tag_list

class User(db.Model):
	"""Standard user class for datastore. Child classes inherit these properties 
	and add their own, and we can grab any post with any key with one database
	pull."""

	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class Content(polymodel.PolyModel):
	"""Parent class for all content classes."""

	created = db.DateTimeProperty(auto_now_add=True)
	tags = db.StringListProperty()
	location = db.StringProperty()
	author = db.StringProperty(required = True)

class Article(Content):
	"""Standard blog post-style Entry class. Uses title as key."""
	title = db.StringProperty(required = True)
	content = db.TextProperty()

class Quote(Content):
	"""Quote-style Entry class. Uses quote as key."""

	quote = db.TextProperty(required = True)
	source = db.StringProperty()

class Image(Content):
	"""Image-style Entry class. Requires title for key, but uses img urls to 
	display content. 

	Would be nice to have imgur custom display implemented soon."""

	title = db.StringProperty(required = True)
	urls = db.StringListProperty(required = True)
	content = db.StringProperty()

class Handler(webapp2.RequestHandler):
	"""Handler class that makes templating more efficient."""

	def write(self, *a, **kw):
		"""Shortens out.write, not essential but nice for testing."""
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		"""Helper function that delivers parameters to the template."""
		t = jinja_env.get_template(template)
		return t.render(params)
	
	def render(self, template, **kw):
		"""Helper function that takes template file and params to generate
		HTML"""

		self.write(self.render_str(template, **kw))

	def pager(self, page_num, class_name, user_name=''):
		if class_name == 'user':
			class_name = 'user=%s' % user_name
		if not page_num:
			page_num = 0
		offset_amount = str((int(page_num)-1) * 10)
		return db.GqlQuery("SELECT * FROM %s ORDER BY created DESC LIMIT 10 OFFSET %s" % (class_name, offset_amount))

class MainPage(Handler):
	def render_page(self):
		page_num = self.request.get("p")
		class_name = 'Content'
		entries = self.pager(page_num, class_name)

		self.render("front_content.html", entries=entries)

	def get(self):
		self.render_page()

class AddPost(Handler):
	def get(self):
		"""First check if user is logged in, and redirect if not."""
		user = self.request.cookies.get('username')
		if not user:
			self.redirect('/login')
		else:
			"""Check if a category has been sent with the request. This will change 
		which form the user has to submit their content and the kind of Content it
		will become."""
			self.render_post()

	def render_post(self):
		cat = self.request.get("cat")
			
		if cat == 'Quote':
			cat = 'Quote'
			self.render("addquote.html", entry=cat)
		elif cat == 'Article':
			cat = 'Article'
			self.render("addpost.html", entry=cat)
		elif cat == 'Image':
			cat = 'Image'
			self.render("addimage.html", entry=cat)
		elif not cat:
			cat = 'Article'
			self.render("addpost.html", entry=cat)

	def post(self):
		""""""
		author = self.request.cookies.get('username').split("|")[0]
		location = self.request.get("location")
		cat = self.request.get("cat")

		tags = self.request.get("tags")
		if tags:
			tags = tagify(tags)
		else:
			tags = []
	
		if cat == 'Quote':
			source = self.request.get("source")
			
			quote = self.request.get("quote")
			quote_list = quote.split(" ")

			key_list = [noAschii(each) for each in quote_list]
			key = "_".join(key_list[10:])

			if quote:
				new_quote = Quote(key_name = key, quote=quote, source=source, location=location, tags=tags, author=author)
				submission = new_quote.put()
				self.redirect("/%s" % key)
			else:
				error = "You must include a quote to submit."
				self.render("addquote.html", quote=quote, source=source, location=location, tags=tags, error=error)
		
		if cat == 'Image':
			title = self.request.get("title")
			urls = self.request.get("urls")

			url_list = urls.split('\r\n')

			title_list = title.split(" ")

			key_list = [noAschii(each) for each in title_list]
			key = "_".join(key_list)

			if title:
				new_image = Image(key_name=key, title=title, urls=url_list, location=location, author=author, tags=tags)
				submission = new_image.put()
				self.redirect("/%s" % key)
			else:
				error = "You must include a title to submit."
				self.render("addimage.html", title=title, urls=urls, location=location, tags=tags, error=error,)

		else:
			title = self.request.get("title")
			content = self.request.get("content")

			title_list = title.split(" ")

			key_list = [noAschii(each) for each in title_list]
			key = "_".join(key_list)

			if title:
				new_article = Article(key_name=key, title=title, content=content, location=location, tags=tags, author=author)
				submission = new_article.put()
				self.redirect("/%s" % key)
			else:
				error = "You must include a title to submit."
				self.render("addpost.html", title=title, content=content, location=location, tags=tags, error=error)

class EditPost(Handler):
	def get(self, key):
		user = self.request.cookies.get('username')
		if not user:
			self.redirect('/login')
		else:
			edited = Content.get_by_key_name(key)
			cat = edited.class_name()
			location = edited.location
			tag_list = edited.tags
			tags = ", ".join(tag_list)

			if cat == 'Quote':
				quote = edited.quote
				source = edited.source
				self.render("addquote.html", entry=cat, quote=quote, source=source, location=location, tags=tags)
				return
			if cat == 'Article':
				title = edited.title
				content = edited.content
				self.render("addpost.html", entry=cat, title=title, content=content, location=location, tags=tags)
				return
			if cat == 'Image':
				title = edited.title
				urls = edited.urls
				url_out = "\r\n".join(urls)
				self.render("addimage.html", entry=cat, title=title, urls=url_out, location=location, tags=tags)
			else:
				self.write("WTF!!!")

	def post(self, key):
		edited = Content.get_by_key_name(key)

		delete = self.request.get("delete")
		if delete:
			deleted = edited.delete()
			self.redirect("/")
		else:
			cat = edited.class_name()
			location = self.request.get("location")
			tag_str = self.request.get("tags")
			author = self.request.cookies.get('username').split("|")[0]

			if tag_str:
				tags = tagify(tag_str)
			else:
				tags = []

			if cat == 'Quote':
				quote = self.request.get("quote")
				source = self.request.get("source")
				if quote:
					revise_quote = Quote(key_name=key, quote=quote, source=source, location=location, tags=tags, author=author)
					submission = revise_quote.put()
					self.redirect("/%s" % key)
				else:
					error = "Please include a quote to submit."
					tags = ", ".join(tags)
					self.render("addquote.html", entry=cat, quote=quote, source=source, location=location, tags=tags, error=error)
			
			elif cat == 'Image':
				title = self.request.get("title")
				urls = self.request.get("urls")
				url_list = urls.split('\r\n')
				if title:
					revise_image = Image(key_name=key, title=title, urls=url_list, location=location, tags=tags, author=author)
					submission = revise_image.put()
					self.redirect("/%s" % key)
				else:
					error = "Please include a title to submit."
					tags = ", ".join(tags)
					self.render("addimage.html", entry=cat, title=title, urls=urls, location=location, tags=tags, error=error)
			
			elif cat == 'Article':
				title = self.request.get("title")
				content = self.request.get("content")
				if title:
					revise_article = Article(key_name=key, title=title, content=content, location=location, tags=tags, author=author)
					submission = revise_article.put()
					self.redirect("/%s" % key)
				else:
					error = "Please include a title to submit."
					tags = ", ".join(tags)
					self.render("addpost.html", entry=cat, title=title, content=content, location=location, tags=tags)

class Post(Handler):
	def get (self, key):
		content = [Content.get_by_key_name(key)]
		self.render("content.html", entries=content)

class UserPage(Handler):
	def get(self, user):
		user = user[1:]

		page_number = self.request.get("p")
		if page_number:
			offset_amount = str((int(page_number)-1) * 10)
			content = db.GqlQuery("SELECT * FROM Content WHERE author = '%s' ORDER BY created DESC LIMIT 10 OFFSET %s" % (offset_amount, user))
		else:
			content = db.GqlQuery("SELECT * FROM Content WHERE author = '%s' ORDER BY created DESC LIMIT 10" % user)

		self.render("content.html", entries=content)

class Login(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		user_name = self.request.get('username')
		user_pass = self.request.get('password')

		q = db.GqlQuery("SELECT * FROM User")
		l = {str(each.username): str(each.password) for each in q}

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
	"""Handler that renders all of the Content with a given tab.

	Could potentially be replaced with a GET query..."""

	def get(self, tag):
		"""Takes URL as tag argument and checks for page number. Runs appropriate 
		GQL query and sends in the results to front_content.html"""

		tag = " ".join(tag[1:].split("_"))
		page_number = self.request.get("p")
		if page_number:
			offset_amount = str((int(page_number)-1) * 10)
			entries = db.GqlQuery("SELECT * FROM Content WHERE tags = '%s' ORDER BY created DESC LIMIT 10 OFFSET %s" % (offset_amount, tag))
		else:
			entries = db.GqlQuery("SELECT * FROM Content WHERE tags = '%s' ORDER BY created DESC LIMIT 10" % tag)

		self.render("content.html", entries=entries)

class Production(Handler):
	def get(self):
		pull = db.GqlQuery("SELECT * FROM Content WHERE author = 'caity'")
		both = []

		for each in pull:
			if each.class_name() == 'Quote':
				both.append(each.quote)
			else:
				both.append(each.title)

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