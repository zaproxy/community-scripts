// Captures Server header from the application response and searches cvedetails.com for known target server vulnerabilities.


function invokeWith(msg) {
	host = msg.getRequestHeader().getURI().getHost(); 
if (msg) 
	{
		headers = msg.getResponseHeader().getHeaders("Server")
		org.zaproxy.zap.utils.DesktopUtils.openUrlInBrowser(
		"http://www.cvedetails.com/google-search-results.php?q=" + headers + "&sa=Search");
	 }
    
}
