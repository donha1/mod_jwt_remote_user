# Prepare
install MSVS if not yet installed, currently it is installed on riapciqa01
download latest httpd lib for windows, extract to a folder D:\httpd-latest, from https://www.apachelounge.com/download/ 
On windows witih MSVS installed:

# Compile, link, build
build.cmd

#Usage
Add this line to Apache conf:
LoadModule bearer_remote_user_module modules/mod_jwt_remote_user.so

The module will read the value from preferred_username field of JWT token and set REMOTE_USER env value with it, the REMOTE_USER can be logged with %u directive.

Sample log entry with userid:
192.168.4.239 - dha [13/Aug/2025:15:17:34 -0400] "PUT /vwc-casper-rest-api/claims/claims/3678086/subresources/RELATED_PARTIES/claimant/address HTTP/2.0" 400 114