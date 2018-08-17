/*
 * Inject Javascript code into a webpage.
 *
 *   - Code will be added inside <script></script> tags in the Response body's
 *   <head></head> before sending it to the client.
 *   - Code to be added is read from the file which path is `FILE` (this need to
 *   be an absolute path, /tmp/test.js in our case).
 *   - Only responses to requests sent by the "proxy initiator" will be modified.
 */

FILE = '/tmp/test.js'

function loadScriptFromFile(file) {
    var Files = Java.type('java.nio.file.Files');
    var Paths = Java.type('java.nio.file.Paths');
    var String = Java.type('java.lang.String');

    var filePath = Paths.get(file);
    return new String(Files.readAllBytes(filePath), 'UTF-8');
}

function sendingRequest(msg, initiator, helper) {}

function responseReceived(msg, initiator, helper) {
    if (initiator != 1) { return; }

    var body = msg.getResponseBody();
    var bodyAsStr = body.toString();
    var header = msg.getResponseHeader();

    var xRequestedWith = msg.getRequestHeader().getHeader('X-Requested-With');
    var contentType = header.getHeader('Content-Type');
    var contentTypeRegex = new RegExp(/text\/html/g);
    var indexOfHead = bodyAsStr.indexOf('<head>');

    if (!contentTypeRegex.test(contentType)
        || xRequestedWith == 'XMLHttpRequest'
        || indexOfHead == -1) {
        return;
    }

    var SCRIPT = '<script>' + loadScriptFromFile(FILE) + '</script>';
    var index = indexOfHead + '<head>'.length();

    var newBody = bodyAsStr.slice(0, index) + SCRIPT + bodyAsStr.slice(index);

    msg.setResponseBody(newBody);
    header.setContentLength(msg.getResponseBody().length());
}
