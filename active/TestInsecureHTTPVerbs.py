"""
Note that new active scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""

"""
Active Scan Python script to test if the webserver has potentially insecure http methods enabled
Author: http://renouncedthoughts.wordpress.com


Tested to work with some of the online vulnerable applications like:
http://zero.webappsecurity.com
http://testaspnet.vulnweb.com
http://testfire.net/
http://crackme.cenzic.com

and other apps from https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project#tab=On-Line_apps

"""

import httplib
import urlparse

insecureverbs=["OPTIONS", "HEAD", "PUT", "DELETE", "TRACE", "CONNECT", "DEBUG", "MOVE", "SEARCH", "PATCH", "MKCOL", "COPY", "LOCK", "UNLOCK", "ARBIT", "XXXX", "12AB"]
acceptedhttpstatuscodesforinsecureverbs=[301, 302, 404, 405, 403, 400, 501]
activevulnerabilitytitle='Potentially Insecure HTTP Verb allowed'
activevulnerabilityfulldescription='Some of the HTTP methods can potentially pose a security risk for a web application, as they allow an attacker to modify the files stored on the web server and, in some scenarios, steal the credentials of legitimate users.' + 'Insecure configuration can possibly lead to web server compromise and website defacement. ' + 'If an application needs one or more of the potentially insecure HTTP methods, such as for REST Web Services (which may require PUT or DELETE), it is important to check that their usage is properly limited to trusted users and safe conditions. ' + 'http://security.stackexchange.com/questions/21413/how-to-exploit-http-methods.'
activevulnerabilitysolution = 'Configure the web server to allow insecure methods like DELETE and PUT only for the relevant resources. ' + 'If your application does not need HTTP methods other than GET and POST, consider disabling the unused HTTP methods.'


def PrepareHTTPRequest(insecureverb, uriparsed):
    connection = httplib.HTTPConnection(uriparsed.hostname, uriparsed.port, 20)
    if insecureverb == "POST" or insecureverb == "PUT":
        connection.request(insecureverb, uriparsed.path, 'bodytext')
    else:
        connection.request(insecureverb, uriparsed.path)    
    return connection


def GetHTTPResponse(insecureverb, uriparsed):
    connection = PrepareHTTPRequest(insecureverb, uriparsed)
    return connection.getresponse();


def PrintAlerts(sas, msg, uri, insecureverb, responsestatuscode, responsestatusmessage):
    attackevidence = 'VERB: \t' + insecureverb + '\t-- STATUS: '+ str(responsestatuscode) +' -- \tMESSAGE: ' + responsestatusmessage
    print (attackevidence)
    sas.raiseAlert(1, 2, activevulnerabilitytitle, activevulnerabilityfulldescription, uri, 'HTTP VERB', 'ZAP sent an HTTP request with method - ' + insecureverb, '', activevulnerabilitysolution, attackevidence, 0, 0, msg);


def TestTheURIForInsecureVerbs(sas, msg, uri, insecureverbs):
    uriparsed = urlparse.urlparse(uri)
    for insecureverb in insecureverbs:
        try:
            httpresponse = GetHTTPResponse(insecureverb, uriparsed)
            if not httpresponse.status in acceptedhttpstatuscodesforinsecureverbs:
                PrintAlerts(sas, msg, uri, insecureverb, httpresponse.status, httpresponse.reason)
        except Exception, e:
		  print('ERROR For: ' + insecureverb + 'Detail: ' + e.message)


def scanNode(sas, msg):
  url = msg.getRequestHeader().getURI().toString()
  print('active scan script called for url=' + url + '\n');
  msg = msg.cloneRequest();
  TestTheURIForInsecureVerbs(sas, msg, url, insecureverbs)


