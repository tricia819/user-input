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

import webapp2
import cgi
import re

# html boilerplate for the top of every page
page_header = """
<!DOCTYPE html>
<html>
<head>
    <title>User Signup</title>
    <style type="text/css">
        .error {
            color: red;
        }
    </style>
</head>
<body>
        <h1>User Signup</h1>
"""

# html boilerplate for the bottom of every page
page_footer = """
</body>
</html>
"""

# Functions to determine if the user's entry is valid.
def valid_username(username):
    username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and username_re.match(username)

def valid_password(password):
    password_re = re.compile(r"^.{3,20}$")
    return password and password_re.match(password)

def valid_email(email):
    email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return email_re.match(email)

# Create a form to sign up new users
signup_form = """
<form method="post">

    <label>
        Username:
        <input type="text" name="username" value="%(username)s"/>&nbsp<span class='error'>%(username_error_msg)s</span><p>
    </label>

    <label>
        Password:
        <input type="password" name="password"/>&nbsp<span class='error'>%(password_error_msg)s</span><p>
    </label>

    <label>
        Verify Password:
        <input type="password" name="verify"/>&nbsp<span class='error'>%(verify_error_msg)s</span><p>
    </label>

    <label>
        Email (Optional):
        <input type="text" name="email"value="%(email)s"/>&nbsp<span class='error'>%(email_error_msg)s</span><p>
    </label>

    <input type="submit" value="Sign Me Up!"/>  <INPUT type="reset">
</form>
"""

# create the page content
content = page_header + signup_form + page_footer


class MainPage(webapp2.RequestHandler):

    """ Handles requests coming in to '/' (the root of our site)
    """
    # puts together the form and page content as it will be written to the screen. Substitute in errors when present.
    def write_form(self, username_error="",  password_error="", verify_error="", email_error="", username="", email=""):
        self.response.write(content % {"username":username,
                                        "email":email,
                                        "username_error_msg":username_error,
                                        "password_error_msg":password_error,
                                        "verify_error_msg":verify_error,
                                        "email_error_msg":email_error})

    # Write the Main Page to the screen
    def get(self):
        self.write_form()


    def post(self):

        # look inside the requests to figure out what the user typed
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        # Initialize the error variables.
        # Per Johnathan Dawson, we do NOT need to escape the HTML on this assignment.
        # cgi.escape("That is not a valid password.", quote=True)
        error = False
        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        # Determine if an error has been thrown. If so, flip the error flag to True.
        if (valid_username(username)) == None:
            username_error = "That's not a valid username"
            error = True

        if (valid_password(password)) == None:
            password_error = "That's not a valid password"
            error = True

        if (password != verify):
            verify_error = "Your passwords don't match."
            error = True

        if (valid_email(email)) == None and email != "":
            email_error = "That's not a valid email address."
            error = True

        if username == "":
            username_error = "The username is a required field. Please enter a username."
            error = True

        if password == "":
            password_error = "The password is a required field. Please enter a username."
            error = True

        # If any of the conditions above triggers an error,
        # rewrite the form to the screen, pass back the error message
        # & the username and email addy to be filled in again.
        if error == True:
            self.write_form(username_error, password_error, verify_error, email_error, username, email)

        # If no errors are present, forward the user to the Welcome Page.
        else:
            self.redirect("/welcome?username=" + username)


class WelcomeHandler(webapp2.RequestHandler):
    """ Handles requests coming in to '/Welcome'
    """
    def get(self):
        # Build and display Welcome Page content
        username = self.request.get("username")
        content = page_header + "<p>" + "<h2>" + "Welcome " + username + "!" + "</h2>" + "</p>" + page_footer
        self.response.write(content)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/welcome', WelcomeHandler)
], debug=True)
