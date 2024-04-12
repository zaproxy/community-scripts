//it will generate and copy curl command based on the request
//released under the Apache v2.0 licence.
//You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//author:@haseebeqx

// Note: The following code lives also in Script Console add-on.

function invokeWith(msg) {
  var string =
    "curl -i -s -k -X  '" + msg.getRequestHeader().getMethod() + "'  \\\n";
  var header = msg.getRequestHeader().getHeadersAsString();
  header = header.split(msg.getRequestHeader().getLineDelimiter());
  var suspiciousHeaders = false;
  for (var i = 0; i < header.length; i++) {
    var headerEntry = header[i].trim();
    if (headerEntry.startsWith("@")) {
      suspiciousHeaders = true;
    }
    // deny listing Host (other deny listing should also specify here)
    var keyval = headerEntry.split(":");
    if (keyval[0].trim() != "Host") string += " -H '" + headerEntry + "' ";
  }
  // if no User-Agent present ensures that curl request doesn't add one
  if (string.indexOf("User-Agent") < 0) string += " -A '' ";
  string += " \\\n";
  var body = msg.getRequestBody().toString();
  if (body.length() != 0) {
    string += "--data-raw $'" + addSlashes(body) + "' \\\n";
  }
  string += "'" + msg.getRequestHeader().getURI().toString() + "'";

  if (!suspiciousHeaders) {
    var selected = new java.awt.datatransfer.StringSelection(string);
    var clipboard = java.awt.Toolkit.getDefaultToolkit().getSystemClipboard();
    clipboard.setContents(selected, null);
  }
  print(string);

  if (suspiciousHeaders) {
    print("\n**WARNING**");
    print(
      "The generated command might be including a local file (e.g. `@/path/to/file`) in a header, carefully review the command before executing it."
    );
    print("Note: The command was *not* added to the clipboard.\n");
  }
}

function addSlashes(body) {
  var a = {};
  a[body] = 1;
  return JSON.stringify(a).slice(2, -4);
}
