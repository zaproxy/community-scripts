// The scan function will be called for request/response made via ZAP, excluding some of the automated tools
// Passive scan rules should not make any requests 

// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// PassiveHTMLCommentFinder.js
// kingthorin+owaspzap@gmail.com

// References:
// RegEx Testing: http://regex101.com/r/tX1hS1
// Initial discussion: https://groups.google.com/forum/#!topic/zaproxy-develop/t-1-yI7iErw\
// RegEx adapted from work by Stephen Ostermiller: http://ostermiller.org/findhtmlcomment.html
// Tweak to RegEx provided by thc202

// NOTE: Designed to work with 2.2 Weekly build version D-2014-03-10 or stable builds at or above v2.3
// NOTE: This script ONLY finds HTML comments. It DOES NOT find JavaScript or other comments.
// NOTE: This script will only find HTML comments in content which passes through ZAP. 
//		Therefore if you browser is caching you may not see something you expect to.

function scan(ps, msg, src) {
	// Both can be true, just know that you'll see duplication.
	RESULT_PER_FINDING = new Boolean(1) // If you want to see results on a per comment basis (i.e.: A single URL may be listed more than once), set this to true (1)
	RESULT_PER_URL = new Boolean(0) // If you want to see results on a per URL basis (i.e.: all comments for a single URL will be grouped together), set this to true (1)
	// These elements are based on the CWE 615 entry as of 20140313
	alertRisk=0
	alertReliability=2
	alertTitle='Information Exposure Through HTML Comments'
	alertDesc='While adding general comments is very useful, \
some programmers tend to leave important data, such as: filenames related to the web application, old links \
or links which were not meant to be browsed by users, old code fragments, etc.'
	alertSolution='Remove comments which have sensitive information about the design/implementation \
of the application. Some of the comments may be exposed to the user and affect the security posture of the \
application.'

	cweId=615 // https://cwe.mitre.org/data/definitions/615.html
	wascId=13 // http://projects.webappsec.org/w/page/13246936/Information%20Leakage

	re = /(\<![\s]*--[\-!@#$%^&*:;ºª.,"'(){}\w\s\/\\[\]]*--[\s]*\>)/g //comments RegEx global match

	url = msg.getRequestHeader().getURI().toString();
	
	println('Finding comments under ' + url); 

	body = msg.getResponseBody().toString()
	if (re.test(body)) {
		re.lastIndex = 0 // After testing reset index
		// Look for html comments
		var foundComments=[]
		var counter=0
		while ( comm = re.exec(body) ) {
			if ( RESULT_PER_FINDING == true ) {
				counter = counter+1;
				ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, 'fakeParam' + counter, '', comm[0], alertSolution, '', cweId, wascId, msg);
			}
		    foundComments.push(comm[0]);
		}
		if ( RESULT_PER_URL == true )
			ps.raiseAlert(alertRisk, alertReliability, alertTitle+' (Rollup)', alertDesc, url, '', '', foundComments.toString(), alertSolution, '', cweId, wascId, msg);
	}
}
