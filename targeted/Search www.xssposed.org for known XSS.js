// Searches www.xssposed.org for known XSS vulnerabilities.
// This script just launches your default browser to perform the search.
const DesktopUtils = Java.type("org.zaproxy.zap.utils.DesktopUtils");

function invokeWith(msg) {
  var host = msg.getRequestHeader().getURI().getHost();

  DesktopUtils.openUrlInBrowser(
    "https://www.xssposed.org/search/?search=" + host + "&type=host"
  );
}
