# Prepare
Install MSVS if not yet installed.
Download latest httpd lib for windows, extract to a folder D:\httpd-latest, from https://www.apachelounge.com/download/. 
On Windows with MSVS installed:

# Compile, link, build
build.cmd

# Usage
Add this line to Apache conf:
LoadModule bearer_remote_user_module modules/mod_jwt_remote_user.so

The module will read the value from preferred_username field of JWT token and set REMOTE_USER env value with it, the REMOTE_USER can be logged with %u directive.

