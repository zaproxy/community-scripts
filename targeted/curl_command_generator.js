//it will generate and copy curl commands based on the request
//released under the Apache v2.0 licence.
//You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//auther:@haseebeqx

function invokeWith(msg) {
	string = "curl -i -s -k -X  '"+msg.getRequestHeader().getMethod().toString()+"'  \\\n";
	header = msg.getRequestHeader().toString();
	header = header.split('\n');
	for(i=1;i<header.length;i++){
		string += " -H '"+header[i].trim()+"' ";
	}
	string += " \\\n";
	body = msg.getRequestBody().toString().trim();
	if(body.length() != 0){
		string += "--data-binary $'"+addSlashes(body)+"' \\\n";
	}
	string += "'"+msg.getRequestHeader().getURI().toString()+"'";
	selected = new java.awt.datatransfer.StringSelection(string);
	clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
	clipboard.setContents(selected,null);
	print (string);
}

function addSlashes(body){
	var a ={}
	a[body] = 1;
	return JSON.stringify(a).slice(2,-4);
}
