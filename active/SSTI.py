"""
github : https://github.com/knassar702/scant3r
--
* Coded by : Khaled Nassar @knassar702
* Version : 0.5#Beta

"""
def scanNode(sas, msg):
  # Copy requests before reusing them
  msg = msg.cloneRequest();

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);

  # Test the responses and raise alerts as below

ssti_payloads = {
    'abcd{{6*6}}123':'abcd36123',
    'abcd${6*6}123':'abcd36123',
    'abcd<% 6*6 %>123':'abcd36123'
    }

def scan(sas, msg, param, value):
  for p,M in ssti_payloads.items():
  # Copy requests before reusing them
    msg = msg.cloneRequest();
  # setParam (message, parameterName, newValue)
    sas.setParam(msg, param, p);
  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    sas.sendAndReceive(msg, False, False);
  # Test the response here, and make other requests as required
    if M in msg.getResponseBody().toString():
  	# Change to a test which detects the vulnerability
    # raiseAlert(risk, int reliability, String name, String description, String uri,
    #		String param, String attack, String otherInfo, String solution, String evidence,
    #		int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # reliability: 0: falsePassitive, 1: suspicious, 2: warning
        sas.raiseAlert(3, 3, 'ScanT3r - Template Injection(SSTI)', 'Template injection allows an attacker to include template code into an existant (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages',msg.getRequestHeader().getURI().toString(), param, p, '', '',M, 0, 0, msg);
