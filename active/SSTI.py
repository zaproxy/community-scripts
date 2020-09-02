"""
github : https://github.com/knassar702/scant3r
--
* Coded by : Khaled Nassar @knassar702
* Email : knassar702@gmail.com
"""

ssti_payloads = {
    'abcd{{6*6}}123':'abcd36123',
    'abcd${6*6}123':'abcd36123',
    'abcd<% 6*6 %>123':'abcd36123'
    }

def scanNode(sas, msg):
  pass

def scan(sas, msg, param, value):
  for payload,evidence in ssti_payloads.items():
    msg = msg.cloneRequest();
    sas.setParam(msg, param, payload);
    sas.sendAndReceive(msg, False, False);
    if evidence in msg.getResponseBody().toString():
      sas.newAlert() \
        .setRisk(3) \
        .setConfidence(3) \
        .setName('Server-side Template Injection (SSTI) (Script)') \
        .setDescription('Template injection allows an attacker to include template code into an existent (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages.') \
        .setUri(msg.getRequestHeader().getURI().toString()) \
        .setParam(param) \
        .setAttack(payload) \
        .setEvidence(evidence) \
        .setMessage(msg) \
        .raise();
      break