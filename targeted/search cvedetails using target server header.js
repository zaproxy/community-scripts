// Captures Server header from the application response and searches cvedetails.com for known target server vulnerabilities.


function invokeWith(msg) {

		headers = msg.getResponseHeader().getHeader("Server")
		org.zaproxy.zap.utils.DesktopUtils.openUrlInBrowser(
		"http://www.cvedetails.com/google-search-results.php?q=" + encodeURIComponent(headers) + "&sa=Search");

    
}
