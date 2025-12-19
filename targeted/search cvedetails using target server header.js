// Captures Server header from the application response and searches cvedetails.com for known target server vulnerabilities.
const DesktopUtils = Java.type("org.zaproxy.zap.utils.DesktopUtils");

function invokeWith(msg) {
  var header = msg.getResponseHeader().getHeader("Server");
  if (header != null) {
    DesktopUtils.openUrlInBrowser(
      "http://www.cvedetails.com/google-search-results.php?q=" +
        encodeURIComponent(header) +
        "&sa=Search"
    );
  }
}
