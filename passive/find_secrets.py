"""
Passive scan rules should not make any requests.

Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"
"""  
# Coded by: Khaled Nassar @knassar702
# Email: knassar702@gmail.com

from org.zaproxy.zap.extension.pscan import PluginPassiveScanner;
import re


regexs = {
            'google_api' : 'AIza[0-9A-Za-z-_]{35}',
            'google_oauth' : 'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id' : '([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}',
            'amazon_mws_auth_toke' : 'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'amazon_aws_url' : 's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
            'firebase_url' : '.firebaseio.com[/]+|[a-zA-Z0-9_-]*\.firebaseio.com',
            'facebook_access_token' : 'EAACEdEose0cBA[0-9A-Za-z]+',
            'authorization_bearer' : 'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
            'mailgun_api_key' : 'key-[0-9a-zA-Z]{32}',
            'twilio_api_key' : 'SK[0-9a-fA-F]{32}',
            'twilio_account_sid' : 'AC[a-zA-Z0-9_\-]{32}',
            'paypal_braintree_access_token' : 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'square_oauth_secret' : 'sq0csp-[ 0-9A-Za-z\-_]{43}',
            'square_access_token' : 'sqOatp-[0-9A-Za-z\-_]{22}',
            'stripe_standard_api' : 'sk_live_[0-9a-zA-Z]{24}',
            'stripe_restricted_api' : 'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token' : '[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key' : '-----BEGIN RSA PRIVATE KEY-----',
            'ssh_dsa_private_key' : '-----BEGIN DSA PRIVATE KEY-----',
            'ssh_dc_private_key' : '-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block' : '-----BEGIN PGP PRIVATE KEY BLOCK-----',
            '!debug_page': "Application-Trace|var TRACEBACK|Routing Error|DEBUG\"? ?[=:] ?True|Caused by:|stack trace:|Microsoft .NET Framework|Traceback|[0-9]:in `|#!/us|WebApplicationException|java\\.lang\\.|phpinfo|swaggerUi|on line [0-9]|SQLSTATE",
            'google_captcha' : '6L[0-9A-Za-z-_]{38}',
            'authorization_api' : 'api[key|\s*]+[a-zA-Z0-9_\-]+',
            'twilio_app_sid' : 'AP[a-zA-Z0-9_\-]{32}',
            'authorization_basic' : 'basic\s*[a-zA-Z0-9=:_\+\/-]+',
            'json_web_token' : 'ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*'
        }


def appliesToHistoryType(historyType):
    """Tells whether or not the scanner applies to the given history type.

    Args:
        historyType (int): The type (ID) of the message to be scanned.

    Returns:
        True to scan the message, False otherwise.

    """
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);


def scan(ps, msg, src):
  """Passively scans the message sent/received through ZAP.

  Args:
    ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
    msg (HttpMessage): The HTTP message being scanned.
    src (Source): The HTML source of the message (if any). 

  """
  rr = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}]({{REGEX}})[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
  for name,match in regexs.items():
      v = rr.replace('{{REGEX}}',match)
      c = re.compile(v)
      mm = c.findall(msg.getResponseBody().toString())
      if len(mm) > 0:
          res = ''
          for i in mm:
              res += i.decode()
    # Change to a test which detects the vulnerability
    # raiseAlert(risk, int confidence, String name, String description, String uri, 
    # String param, String attack, String otherInfo, String solution, String evidence, 
    # int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
    # confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
          ps.raiseAlert(3, 3, '[Find Secrets] {}'.format(name), '', msg.getRequestHeader().getURI().toString(), name,'', 'Regex: {v}'.format(v=v), '', res, 0, 0, msg);
