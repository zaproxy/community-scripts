//it will generate and copy sqlmap command based on the request
//released under the Apache v2.0 licence.
//You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//author: @juliosmelo


function invokeWith(msg) {
	var string = "sqlmap --url '"+msg.getRequestHeader().getURI().toString()+"' \\\n";
	var header = msg.getRequestHeader().getHeadersAsString();
	header = header.split(msg.getRequestHeader().getLineDelimiter());

	for(var i=0;i<header.length;i++){
		string += " -H '"+header[i].trim()+"' ";
	}
	string += " \\\n";
	var body = msg.getRequestBody().toString();
	if(body.length() != 0){
		string += "--data='"+addSlashes(body)+"'";
	}
	var selected = new java.awt.datatransfer.StringSelection(string);
	var clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
	clipboard.setContents(selected, null);
	print (string);
}

function addSlashes(body){
	var a ={}
	a[body] = 1;
	return JSON.stringify(a).slice(2,-4);
}