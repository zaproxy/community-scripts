"""
github : https://github.com/knassar702/scant3r
--
* Coded by : Khaled Nassar @knassar702
* Email : knassar702@gmail.com

"""
follow_redirects = False
def scanNode(sas, msg):
  pass

rce_payloads = {
    '''
cat${IFS}/etc/passwd''':'root:x:0:0',
    '''
cat /etc/passwd''':'root:x:0:0',
    '''
uname''':'gid='
    }

def scan(sas, msg, param, value):
  for payload,message in rce_payloads.items():
    msg = msg.cloneRequest();
    sas.setParam(msg, param, payload);
    sas.sendAndReceive(msg, follow_redirects, False);
    if message in msg.getResponseBody().toString():
      sas.newAlert() \
        .setRisk(3) \
        .setConfidence(3) \
        .setName('Remote Code Execution (Script)') \
        .setDescription('Attack technique used for unauthorized execution of operating system commands. This attack is possible when an application accepts untrusted input to build operating system commands in an insecure manner involving improper data sanitization, or improper calling of external programs.') \
        .setUri(msg.getRequestHeader().getURI().toString()) \
        .setParam(param) \
        .setAttack(payload) \
        .setEvidence(message) \
        .setMessage(msg) \
        .raise();
      break
