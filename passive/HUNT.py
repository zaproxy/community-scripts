import re
from org.zaproxy.zap.extension.script import ScriptVars

'''find possible vulnerable entry points using Hunt Methodology - https://github.com/bugcrowd/HUNT'''


def appliesToHistoryType(histType):
    """
    Limit scanned history types, which otherwise default to
    types in `PluginPassiveScanner.getDefaultHistoryTypes()`
    """
    from org.parosproxy.paros.model import HistoryReference as hr

    return histType in [hr.TYPE_PROXIED, hr.TYPE_SPIDER]


def find_words_in_params(param_list, word_list):
    result = []
    for word in word_list:
        for param in param_list:
            if word in param:
                result.append(word)
    return result


def hunt_alert(ps, msg, uri, result, title, desc):
    if not result:
        return

    result_repr = ','.join(result)
    title += " (HUNT script)"
    desc = desc.strip().format(result=result_repr)

    info = msg.getRequestHeader().toString()
    info += "\n" + msg.getRequestBody().toString()

    # Docs on alert raising function:
    #  raiseAlert(int risk, int confidence, str name, str description, str uri,
    #             str param, str attack, str otherInfo, str solution,
    #             str evidence, int cweId, int wascId, HttpMessage msg)
    #  risk: 0: info, 1: low, 2: medium, 3: high
    #  confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
    ps.raiseAlert(0, 1, title, desc, uri, result_repr,
            None, info, None, None, 0, 0, msg)


def scan(ps, msg, src):
    words_dlp = ['access','admin','dbg','debug','edit','grant','test','alter','clone','create','delete','disable','enable','exec','execute','load','make','modify','rename','reset','shell','toggle','adm','root','cfg','config']
    words_pfi = ['file','document','folder','root','path','pg','style','pdf','template','php_path','doc']
    words_pidor = ['id','user','account','number','order','no','doc','key','email','group','profile','edit','report']
    words_prce = ['daemon','host' ,'upload','dir','execute','download','log','ip','cli','cmd']
    words_psql = ['id','select','report','role','update','query','user','name','sort','where','search','params','process','row','view','table','from','sel','results','sleep','fetch','order','keyword','column','field','delete','string','number','filter']
    words_pssrf = ['dest','redirect','uri','path','continue','url','window','next','data','reference','site','html','val','validate','domain','callback','return','page','feed','host','port','to','out','view','dir','show','navigation','open']
    words_pssti = ['template','preview','id','view','activity','name','content','redirect']

    uri = msg.getRequestHeader().getURI().toString()
    params = [p.lower() for p in msg.getParamNames()]

    base_uri = re.search('^https?://[^/]+/[^?#=]*', uri)

    if not params or not base_uri:
        return

    base_uri = base_uri.group()
    urlParam_repr = base_uri + str(params)
    globalvar = max(ScriptVars.getGlobalVar("hunt"), "")

    if urlParam_repr in globalvar:
        return

    ScriptVars.setGlobalVar("hunt", globalvar + ' , ' + urlParam_repr)

    # Searching Debug and Logic
    result = find_words_in_params(params, words_dlp)
    hunt_alert(ps, msg, uri, result,
    "Possible Debug & Logic Parameters", """
HUNT located the {result} parameter inside of your application traffic. \
The {result} parameter is most often associated to debug, access, or \
critical functionality in applications.

HUNT recommends further manual analysis of the parameter in question.
""")

    # Searching File Inclusion
    result = find_words_in_params(params, words_pfi)
    hunt_alert(ps, msg, uri, result,
    "Possible File Inclusion or Path Traversal", """
HUNT located the {result} parameter inside of your application traffic. \
The {result} parameter is most often susceptible to \
File Inclusion or Path Traversal.

HUNT recommends further manual analysis of the parameter in question.

Also note that several parameters from this section and SSRF might overlap or \
need testing for both vulnerability categories.

For File Inclusion or Path Traversal HUNT recommends the following resources \
to aid in manual testing:

- The Web Application Hackers Handbook: \
Chapter 10
- LFI Cheat Sheet: https://highon.coffee/blog/lfi-cheat-sheet/
- Gracefuls Path Traversal Cheat Sheet: Windows: \
https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/
- Gracefuls Path Traversal Cheat Sheet: Linux: \
https://www.gracefulsecurity.com/path-traversal-cheat-sheet-linux/
""")

    # Searching IDORs
    result = find_words_in_params(params, words_pidor)
    hunt_alert(ps, msg, uri, result,
    "Possible IDOR", """
HUNT located the {result} parameter inside of your application traffic. \
The {result} parameter is most often susceptible to \
Insecure Direct Object Reference Vulnerabilities.

Direct object reference vulnerabilities occur when there are insufficient \
authorization checks performed against object identifiers used in requests. \
This could occur when database keys, filenames, or other identifiers are used \
to directly access resources within an application.
These identifiers would likely be predictable (an incrementing counter, \
the name of a file, etc), making it easy for an attacker to detect this \
vulnerability class. If further authorization checks are not performed, this \
could lead to unauthorized access to the underlying data.

HUNT recommends further manual analysis of the parameter in question.

For Insecure Direct Object Reference Vulnerabilities HUNT recommends the \
following resources to aid in manual testing:

- The Web Application Hackers Handbook: \
Chapter 8
- Testing for Insecure Direct Object References (WSTG-ATHZ-04): \
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html
- Using Burp to Test for Insecure Direct Object References: \
https://support.portswigger.net/customer/portal/articles/1965691-using-burp-to-test-for-insecure-direct-object-references
- IDOR Examples from ngalongc/bug-bounty-reference: \
https://github.com/ngalongc/bug-bounty-reference#insecure-direct-object-reference-idor
""")

    # Searching RCEs
    result = find_words_in_params(params, words_prce)
    hunt_alert(ps, msg, uri, result,
    "Possible RCE", """
HUNT located the {result} parameter inside of your application traffic. \
The {result} parameter is most often susceptible to OS Command Injection.

HUNT recommends further manual analysis of the parameter in question.

For OS Command Injection HUNT recommends the following resources to aid \
in manual testing:

- (OWASP) Testing for OS Command Injection (WSTG-INPV-12): \
https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection.html
- Joberts How To Command Injection: \
https://www.hackerone.com/blog/how-to-command-injections
- Commix Command Injection Tool: \
https://github.com/commixproject/commix
-The FuzzDB OS CMD Exec section: \
https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/os-cmd-execution
- Ferruh Mavitunas CMDi Cheat Sheet: \
https://ferruh.mavituna.com/unix-command-injection-cheat-sheet-oku/
- The Web Application Hackers Handbook: Chapter 10
""")

    # Searching SQLi
    result = find_words_in_params(params, words_psql)
    hunt_alert(ps, msg, uri, result,
    "Possible SQLi", """
HUNT located the {result} parameter inside of your application traffic. \
The {result} parameter is most often susceptible to SQL Injection.

HUNT recommends further manual analysis of the parameter in question.

For SQL Injection HUNT references The Bug Hunters Methodology \
SQL Injection references table:

- PentestMonkeys MySQL Injection Cheat Sheet: \
http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
- Reiners MySQL Injection Filter Evasion: \
https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/
- EvilSQLs Error/Union/Blind MSSQL Cheat Sheet: \
http://evilsql.com/main/page2.php
- PentestMonkeys MSSQL SQL Injection Cheat Sheet: \
http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- PentestMonkeys Oracle SQL Cheat Sheet: \
http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet
- PentestMonkeys PostgreSQL Cheat Sheet: \
http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet
- Access SQL Injection Cheat Sheet: \
http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html
- PentestMonkeys Ingres SQL Injection Cheat Sheet: \
http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet
- PentestMonkeys DB2 SQL Injection Cheat Sheet: \
http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet
- PentestMonkeys Informix SQL Injection Cheat Sheet: \
http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet
- SQLite3 Injection Cheat Sheet: \
https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet
- Ruby on Rails (ActiveRecord) SQL Injection Guide: \
https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet
""")

    # Searching SSRF
    result = find_words_in_params(params, words_pssrf)
    hunt_alert(ps, msg, uri, result,
    "Possible SSRF", """
HUNT located the {result} parameter inside of your application traffic. \
The {result} parameter is most often susceptible to \
Server Side Request Forgery (and sometimes URL redirects).

HUNT recommends further manual analysis of the parameter in question.

For Server Side Request Forgery HUNT recommends the following resources to \
aid in manual testing:

- Server-side browsing considered harmful - Nicolas Gregoire: \
http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf
- How To: Server-Side Request Forgery (SSRF) - Jobert Abma: \
https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF
- SSRF Examples from ngalongc/bug-bounty-reference: \
https://github.com/ngalongc/bug-bounty-reference#server-side-request-forgery-ssrf
- Safebuff SSRF Tips: \
http://blog.safebuff.com/2016/07/03/SSRF-Tips/
- The SSRF Bible: \
https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit
""")

    # Searching SSTI
    result = find_words_in_params(params, words_pssti)
    hunt_alert(ps, msg, uri, result,
    "Possible SSTI", """
HUNT located the {result} parameter inside of your application traffic. \
The {result} parameter is most often susceptible to \
Server Side Template Injection.

HUNT recommends further manual analysis of the parameter in question.
""")
