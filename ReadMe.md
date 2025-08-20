# Overview
This Apache module, writen in c for Windows, parses JWTs from Bearer tokens and maps a claim (like preferred_username). Its purpose is to extract a username (or other configured claim) from a JSON Web Token (JWT) passed in the HTTP Authorization: Bearer <token> header and set it as the Apache environment variable REMOTE_USER.
# Prepare
Install MSVS if not yet installed.
Download latest httpd lib for windows, extract to a folder D:\httpd-latest, from https://www.apachelounge.com/download/. 
On windows witih MSVS installed:

# Compile, link, build
build.cmd<br>
copy the output, mod_jwt_remote_user.so, to modules folder of Apache
# Usage
Add this line to Apache conf:
LoadModule bearer_remote_user_module modules/mod_jwt_remote_user.so

The module will read the value from preferred_username field of JWT token and set REMOTE_USER env value with it, the REMOTE_USER can be logged with %u directive.
To override this default claim, add this line to conf to change username claim to, for example,  email:<br>
JWTRemoteUserClaim  email<br>

Sample log entry with userid:

192.168.4.239 - jsmith [13/Aug/2025:15:17:34 -0400] "PUT /rest-api/claims/claims/4678086/subresources/claimant/address HTTP/2.0" 200 114

