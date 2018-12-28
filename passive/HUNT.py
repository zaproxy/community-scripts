import re
from org.zaproxy.zap.extension.script import ScriptVars

''' find possible vulnerable entry points using Hunt Methodology - https://github.com/bugcrowd/HUNT'''


def appliesToHistoryType(histType):
    """
    Limit scanned history types, which otherwise default to
    types in `PluginPassiveScanner.getDefaultHistoryTypes()`
    """
    from org.parosproxy.paros.model import HistoryReference as hr

    return histType in [hr.TYPE_PROXIED, hr.TYPE_SPIDER]


def scan(ps, msg, src):
    if ScriptVars.getGlobalVar("hunt") is None:
        ScriptVars.setGlobalVar("hunt","init")

    words_dlp = ['access','admin','dbg','debug','edit','grant','test','alter','clone','create','delete','disable','enable','exec','execute','load','make','modify','rename','reset','shell','toggle','adm','root','cfg','config']
    words_pfi = ['file','document','folder','root','path','pg','style','pdf','template','php_path','doc']
    words_pidor = ['id','user','account','number','order','no','doc','key','email','group','profile','edit','report']
    words_prce = ['daemon','host' ,'upload','dir','execute','download','log','ip','cli','cmd']
    words_psql = ['id','select','report','role','update','query','user','name','sort','where','search','params','process','row','view','table','from','sel','results','sleep','fetch','order','keyword','column','field','delete','string','number','filter']
    words_pssrf = ['dest','redirect','uri','path','continue','url','window','next','data','reference','site','html','val','validate','domain','callback','return','page','feed','host','port','to','out','view','dir','show','navigation','open']
    words_pssti = ['template','preview','id','view','activity','name','content','redirect']
    uri = msg.getRequestHeader().getURI().toString()
    params = msg.getParamNames()
    params = [element.lower() for element in params]

    base_uri = re.search('https?:\/\/([^/]+)(\/[^?#=]*)',uri)

    if base_uri:
        base_uri = str( base_uri.group() )
        regex = base_uri + str(params)
        globalvar = ScriptVars.getGlobalVar("hunt")

        if regex not in globalvar:
            ScriptVars.setGlobalVar("hunt","" + globalvar + ' , ' + regex)

            # Searching Debug and Logic
            result = []
            for x in words_dlp:
                y = re.compile(".*"+x)
                if len(filter(y.match, params))>0:
                    result.append(x)

            if result:
                ps.raiseAlert(0, 1, 'Possible Debug & Logic Parameters', 'HUNT located the' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often associated to debug,  access, or critical functionality in applications. \nHUNT recommends further manual analysis of the parameter in question.',
                msg.getRequestHeader().getURI().toString(),
                ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);

            # Searching File Inclusion
            result = []
            for x in words_pfi:
                y = re.compile(".*"+x)
                if len(filter(y.match, params))>0:
                    result.append(x)

            if result:
                ps.raiseAlert(0, 1, 'Possible File Inclusion or Path Traversal', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to File Inclusion or Path Traversal. HUNT recommends further manual analysis of the parameter in question. Also note that several parameters from this section and SSRF might overlap or need testing for both vulnerability categories.\n\nFor File Inclusion or Path Traversal HUNT recommends the following resources to aid in manual testing:\n\n- The Web Application Hackers Handbook: Chapter 10\n- LFI Cheat Sheet: https://highon.coffee/blog/lfi-cheat-sheet/ \n- Gracefuls Path Traversal Cheat Sheet: Windows: https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/ \n- Gracefuls Path Traversal Cheat Sheet: Linux: https://www.gracefulsecurity.com/path-traversal-cheat-sheet-linux/',
                msg.getRequestHeader().getURI().toString(),
                ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);

            # Searching IDORs
            result = []
            for x in words_pidor:
                y = re.compile(".*"+x)
                if len(filter(y.match, params))>0:
                    result.append(x)

            if result:
                ps.raiseAlert(0, 1, 'Possible IDOR', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to Insecure Direct Object Reference Vulnerabilities. \n\nDirect object reference vulnerabilities occur when there are insufficient authorization checks performed against object identifiers used in requests. This could occur when database keys, filenames, or other identifiers are used to directly access resources within an application. \nThese identifiers would likely be predictable (an incrementing counter, the name of a file, etc), making it easy for an attacker to detect this vulnerability class. If further authorization checks are not performed, this could lead to unauthorized access to the underlying data.\nHUNT recommends further manual analysis of the parameter in question.\n\nFor Insecure Direct Object Reference Vulnerabilities HUNT recommends the following resources to aid in manual testing:\n\n- The Web Application Hackers Handbook: Chapter 8\n- Testing for Insecure Direct Object References (OTG-AUTHZ-004): https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004) \n- Using Burp to Test for Insecure Direct Object References: https://support.portswigger.net/customer/portal/articles/1965691-using-burp-to-test-for-insecure-direct-object-references\n- IDOR Examples from ngalongc/bug-bounty-reference: https://github.com/ngalongc/bug-bounty-reference#insecure-direct-object-reference-idor',
                msg.getRequestHeader().getURI().toString(),
                ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);

            # Searching RCEs
            result = []
            for x in words_prce:
                y = re.compile(".*"+x)
                if len(filter(y.match, params))>0:
                    result.append(x)

            if result:
                ps.raiseAlert(0, 1, 'Possible RCE', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to OS Command Injection. HUNT recommends further manual analysis of the parameter in question.\n\nFor OS Command Injection HUNT recommends the following resources to aid in manual testing:\n\n- (OWASP) Testing for OS Command Injection: https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)\n- Joberts How To Command Injection: https://www.hackerone.com/blog/how-to-command-injections \n- Commix Command Injection Tool: https://github.com/commixproject/commix\n-The FuzzDB OS CMD Exec section: https://github.com/fuzzdb-project/fuzzdb/tree/master/attack/os-cmd-execution \n- Ferruh Mavitunas CMDi Cheat Sheet: https://ferruh.mavituna.com/unix-command-injection-cheat-sheet-oku/ \nThe Web Application Hackers Handbook: Chapter 10',
                msg.getRequestHeader().getURI().toString(),
                ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);

            # Searching SQLi
            result = []
            for x in words_psql:
                y = re.compile(".*"+x)
                if len(filter(y.match, params))>0:
                    result.append(x)

            if result:
                ps.raiseAlert(0, 1, 'Possible SQLi', 'HUNT located the parameter inside of your application traffic. The parameter is most often susceptible to SQL Injection. HUNT recommends further manual analysis of the parameter in question.\n\nFor SQL Injection HUNT references The Bug Hunters Methodology SQL Injection references table:\n\n- PentestMonkeys MySQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet \n\n- Reiners MySQL Injection Filter Evasion: https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/ \n- EvilSQLs Error/Union/Blind MSSQL Cheat Sheet: http://evilsql.com/main/page2.php \n- PentestMonkeys MSSQL SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet \n- PentestMonkeys Oracle SQL Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet \n- PentestMonkeys PostgreSQL Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet \n- Access SQL Injection Cheat Sheet: http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html \n- PentestMonkeys Ingres SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/ingres-sql-injection-cheat-sheet \n- PentestMonkeys DB2 SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet \n- PentestMonkeys Informix SQL Injection Cheat Sheet: http://pentestmonkey.net/cheat-sheet/sql-injection/informix-sql-injection-cheat-sheet \n- SQLite3 Injection Cheat Sheet: https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet \n- Ruby on Rails (ActiveRecord) SQL Injection Guide: https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet',
                msg.getRequestHeader().getURI().toString(),
                ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '',
                '', 0, 0, msg);

            # Searching SSRF
            result = []
            for x in words_pssrf:
                y = re.compile(".*"+x)
                if len(filter(y.match, params))>0:
                    result.append(x)

            if result:
                ps.raiseAlert(0, 1, 'Possible SSRF', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to Server Side Request Forgery (and sometimes URL redirects). HUNT recommends further manual analysis of the parameter in question.\n\nFor Server Side Request Forgery HUNT recommends the following resources to aid in manual testing:\n\n- Server-side browsing considered harmful - Nicolas Gregoire: http://www.agarri.fr/docs/AppSecEU15-Server_side_browsing_considered_harmful.pdf \n- How To: Server-Side Request Forgery (SSRF) - Jobert Abma: https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF \n- SSRF Examples from ngalongc/bug-bounty-reference: https://github.com/ngalongc/bug-bounty-reference#server-side-request-forgery-ssrf \n- Safebuff SSRF Tips: http://blog.safebuff.com/2016/07/03/SSRF-Tips/ \n- The SSRF Bible: https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit',
                msg.getRequestHeader().getURI().toString(),
                ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);

            # Searching SSTI
            result = []
            for x in words_pssti:
                y = re.compile(".*"+x)
                if len(filter(y.match, params))>0:
                    result.append(x)

            if result:
                ps.raiseAlert(0, 1, 'Possible SSTI', 'HUNT located the ' + ','.join(result) + ' parameter inside of your application traffic. The ' + ','.join(result) + ' parameter is most often susceptible to Server Side Template Injection. HUNT recommends further manual analysis of the parameter in question.',
                msg.getRequestHeader().getURI().toString(),
                ','.join(result), '', msg.getRequestHeader().toString()+'\n'+msg.getRequestBody().toString(), '', '', 0, 0, msg);
