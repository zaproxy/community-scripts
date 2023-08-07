# A scan hook (https://www.zaproxy.org/docs/docker/scan-hooks/) which adds a script for logging all requests.
# To use this script copy it and the httpsender/LogRequests.js script to your CWD.
# Then run ZAP like this:
#     docker run -v $(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://www.example.com --hook=LogMessagesHook.py
# The requests and responses should be written to a req-resp-log.txt file in the CWD.

def zap_started(zap, target):
  zap.script.load('LogMessages.js', 'httpsender', 'Oracle Nashorn', '/zap/wrk/LogMessages.js')
  zap.script.enable('LogMessages.js')
