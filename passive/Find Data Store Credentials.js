//***************************************
//
// Find Data Store Credentials.js
// 10-JAN-2016
// Josh Bowser
// jkbowser[at]gmail[dot]com
// 
// Credits to Mikey and Hillj for the sanity check
// Credit to http://regexr.com allowing me to test my shakey regexp
//***************************************

//This JavaScript will tell ZAP to regexp test for some well known 
//RDBMS connection string key words in a response body to see if any are leaked out to the client
//Unlikely to find matches?  Yes, but I've seen this done twice now in various pen tests
//so I figured it was time to add a script to check for it

function scan(ps, msg, src)
{
    url = msg.getRequestHeader().getURI().toString(); //For tracking the request
    body = msg.getResponseBody().toString() //get the body so we can test against our regexp
    alertRisk = 3 //High risk hardcoded
    alertReliability = 1 //low confidence hardcoded
    alertTitle = "Database Credentials Exposed"
    alertDesc = "Database credentials are exposed to the client. Review Other Info carefully and manually inspect the response to confirm"
    alertSolution = "Do not pass database connection strings, key/value pair data or credentials to the client"
    cweId = 0 //?
    wascId = 0  //?

	//Regexp for different connection string keywords. Tried to group them for readability. 

	//server
	svr = /server\s*=([^;]*);?/gi //match any case-insensitive to: server<possible space(s)>=<any non-semicolon char>;<optional ;>

	//database names
	db = /database\s*=([^;]*);?/gi //match any case-insensitive to: database<possible space(s)>=<any non-semicolon char>;<optional ;>
	ds = /data source\s*=([^;]*);?/gi //match any case-insensitive to: data source<possible space(s)>=<any non-semicolon char>;<optional ;>
	ic = /initial catalog\s*=([^;]*);?/gi //match any case-insensitive to: initial catalog<possible space(s)>=<any non-semicolon char>;<optional ;>
	
	//usernames
	un = /user\s?name\s*=([^;]*);?/gi //match any case-insensitive to: user<possible space>name<possible space(s)>=<any non-semicolon char>;<optional ;>
	ui = /user\s?id\s*=([^;]*);?/gi //match any case-insensitive to: user<possible space>id<possible space(s)>=<any non-semicolon char>;<optional ;>
	uid = /uid\s*=([^;]*);?/gi //match any case-insensitive to: uid<possible space(s)>=<any non-semicolon char>;<optional ;>

	//password
	pw = /password\s*=([^;]*);?/gi //match any case-insensitive to: password<possible space(s)>=<any non-semicolon char>;<optional ;>
	pwd = /pwd\s*=([^;]*);?/gi //match any case-insensitive to: pwd<possible space(s)>=<any non-semicolon char>;<optional ;>

	//dump into array
	dataSourceCheck = [svr, db, ds, ic, un, ui, uid, pw, pwd]

	//create an array for matching strings as we might have more than 1 hit
	var credsFound = []

	//now for loop through the array
	for (var i=0; i < dataSourceCheck.length; i++)
	{

		//If test the body against our regexp array
		if(dataSourceCheck[i].test(body)) //test() returns true/false boolean so we know to continue
		{
	
			//set this to 0 as we're in a loop and this is a stateful object, so we always want to make sure
			//we are starting at the beginning of the response
			dataSourceCheck[i].lastIndex = 0 

			//exec() returns the matching string(s), so keep looking until we find no more matches
			while (comm = dataSourceCheck[i].exec(body)) 
			{
				//Append additional hits to credsFound array as the above exec() might have multiple matches through the while loop
				credsFound.push(comm[0]); 
			}

		}
	}

	//check to see if we found anything
	//if not 0, we found at least 1 match, so alert it
	//if 0, we found nothing, so end
	if (credsFound.length != 0)
	{

		//finally, we have our array of hits, raise the alert
		ps.raiseAlert(alertRisk
			, alertReliability
			, alertTitle
			, alertDesc
			, url
			, 'Parm Not Used'
			, 'Attack Not Used'
			, credsFound.toString() //these are the matching db credential strings
			, alertSolution
			, 'See Other Info Section'
			, cweId
			, wascId
			, msg);		
	}

}
