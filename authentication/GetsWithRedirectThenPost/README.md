## What is this project

ZAP Autentication script that handles several GETs with HTTP 302 redirect and a post. All GETs and POST set cookies that are required
A php back-end is provided for testing purposes.

## php example authentication scheme description
In order to authenticate, the user needs to GET /get1.php, follow redirects then post on post.php by clicking the "Login" button. This is what happens in details:
* /get1.php
    * redirects to /get2.php
* /get2.php
    * sets get2cookie with a value equal the timestamp at the minute precision
    * redirects to /get3.php
* /get3.php
    * check get2cookie presence and value
    * sets get3cookie with a value equal the timestamp at the minute precision
    * redirects to /get4.php
* /get4.php
    * check get2cookie and get3cookie presence and value
    *  displays "this is get4" and a login button
* /post.php
    * check get2cookie and get3cookie presence and value
    * sets postcookie with a value equal the timestamp at the minute precision
    
When accessing /test.php, the 3 cookies presence and values are checked. If they are more than 1 mn old, it will trigger the "Authentification error" message that can be used as a "logged out indicator".

Consequently, when attacking /test.php with the active scan, the authentication script should be triggered once every minute.
The php script also logs information in apache log file /var/log/apache2/error.log

## How to use
### Adding the script
* View / show tabs / scripts tab
* Right click on "authentication" / new script
    * Script name: GetsWithRedirectThenPost
    * Type: authentication
    * Script engine: ECMAScript 
* Paste the script content

### Setting the session
* Double-click on the context
* authentication
    * script-based authentication
    * select GetsWithRedirectThenPost then click "load"
    * "username field": username (doesn't really matter for us; this is the parameter name that will be used to provide the credential in post.php)
    * "password field": password (same remark)
    * "Fist get URI with leading slash, without trailing slash": /test/get1.php
    * "Hostname without trailing slash": https://myhostname.com
    * Regex pattern identified in Logged in response message: leave empty
    * Regex pattern identified in Logged out response message: Authentification error
* Users
    * Add a "myuser" user
    * usernamefield: usernamevalue
    * passwordfield: passwordvalue
* Forced user
    * select "myuser"

With the above example, POST will be done with the body: "username=usernamevalue&password=passwordvalue".

NB: If attacking the site from the root (which is not the described method here), don't forget to exclude all login pages from the context (get*.php and post.php).
	
### Setting the php back-end
Upload the provided php scripts into a webserver of your own, under /test folder (for apache: /var/www/html/test)
 
### Attacking
* Browse manually to https://myhostname.com/test/get1.php
    * you should be redirected to get4.php and see the message "this is get4" with a login button
* Click the login button
* Click the "click here" link

IF you did all this within a minute, test.php should only display "this is only a test"

* In ZAP
    * Tools / options / active scan (this is just to make further analysis easier)
       * Number of host scanned concurrently : 1
       * Delay when scanning in ms: 1000
    * Click the "forced user mode" button
    * Under "Sites" tab, unfold until test.php
    * Right click / Attack / active scan
        * select "myuser" user and click "start scan" 

Expected result: 
* History tab: the authentication requests are logged here:
    * get1.php: code 302
    * get2.php: code 302
    * get3.php: code 302
    * get4.php: code 200
    * post.php: code 200
       
Every new minute, the same sequence described above should produce. 
* Active scan tab: you can check the value of the cookies in the test.php attack requests
* Scripts tab: some information are also displayed here, printed by the js script

### Troubleshooting
* The authentication script never triggers
    * Check that the "forced user mode" button is clicked (needs to be checked every time ZAP restart)
    * Check the "logged out indicator"
* The GET cookies from redirects are not set in requests
    * Check the URL built from the hostname and the URI in the script: if there is an additional / between the host and the URI (https://hostname//uri) it may prevent cookies from being set from the HttpState into the RequestMessage 
* I have a redirect on POST and the cookie is not persisted into the HttpState
    * This script doesn't cover this scenario. See a workaround in TwoStepAuthentication.js
   
## Technical information
### sendAndReceive parameters
This script uses sendAndReceive with 2nd parameter false in order not to follow automatically redirects: this allows us to manually add the redirect request/responses in ZAP history, making it much easier to understand what is going on. 
With followRedirect=true, all request/responses and their cookies are aggregated in a single line in ZAP history tab.
When getting get1.php, this is what would be displayed (as of ZAP 2.7.0):
* URL: get1.php (the fist redirect location)
* Request 
    * cookies: get2Cookie, get3Cookie
* Response 
    * cookies: get2Cookie, get3Cookie
    * body: the get4.php server response (the last redirect followed)


### Re-usable functions
* doGet: Makes 1 get request
* doPost: Makes 1 POST request
* listRequestCookies : prints the cookies in the request and their value
* doLog : print a timestamped message (need getNow function)


