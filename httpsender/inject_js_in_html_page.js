/*
 * Inject Javascript code into a webpage.
 *
 *   - Code will be added inside <script></script> tags in the Response body's
 *   <head></head> before sending it to the client.
 *   - Code to be added is read from the file which path is `FILE` (this need to
 *   be an absolute path, /tmp/test.js in our case).
 */

FILE = '/tmp/test.js'
SCRIPT = '\t<script>' + loadScriptFromFile(FILE) + '</script>\n';

function loadScriptFromFile(file) {
    Files = Java.type('java.nio.file.Files');
    Paths = Java.type('java.nio.file.Paths');
    String = Java.type('java.lang.String');

    filePath = Paths.get(file);
    return new String(Files.readAllBytes(filePath), 'UTF-8');
}

function sendingRequest(msg, initiator, helper) {}

function responseReceived(msg, initiator, helper) {
    body = msg.getResponseBody();
    bodyAsStr = body.toString();
    header = msg.getResponseHeader();

    xRequestedWith = msg.getRequestHeader().getHeader('X-Requested-With');
    contentType = header.getHeader('Content-Type');

    contentTypeRegex = new RegExp(/text\/html;/g);

    if (!contentTypeRegex.test(contentType)
        || xRequestedWith == 'XMLHttpRequest') {
        return true;
    }

    index = body.toString().indexOf('<head>') + '<head>\n'.length();

    newBody = bodyAsStr.slice(0, index) + SCRIPT + bodyAsStr.slice(index);
    header.setContentLength(newBody.length() + 1);

    msg.setResponseBody(newBody);
}
