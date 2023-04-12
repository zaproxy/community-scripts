/**
 * Contributed by Astra Security (https://www.getastra.com/)
 * @author Prince Mendiratta <prince.mendiratta@getastra.com>
 */

var pluginid = 100032;

var URI = Java.type("org.apache.commons.httpclient.URI");
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference");
var ExtensionAlert = Java.type("org.zaproxy.zap.extension.alert.ExtensionAlert");
var Alert = Java.type("org.parosproxy.paros.core.scanner.Alert");

var session = model.getSession();
var extLoader = control.getExtensionLoader();

// Print statements using script name
function logger() {
    print("[" + this["zap.script.name"] + "] " + arguments[0]);
}

/**
 * Check for user enumeration on WordPress through author archives.
 * 
 * A function which will be invoked against a specific "targeted" message.
 * 
 * @param msg - the HTTP message being acted upon. This is an HttpMessage object.
 */
function invokeWith(msg) {

    var url = msg.getRequestHeader().getURI().toString();
    var alertName = "WordPress Username Enumeration";
    var alertDesc = "The username for user login has been exposed through author archives. This can allow for bruteforcing the password for the respective username and gain access to the admin dashboard.";
    var alertSol = "Make sure that URLs with query parameter " + url + "/?author={integer} and " + url + "/wp-json/wp/v2/users are not accessible publicly.";
    var alertReference = "https://www.getastra.com/blog/cms/wordpress-security/stop-user-enumeration/";
    var cweId = 203; // Observable Discrepancy
    var wascId = 13; // Information Leakage

    // To check if script is running
    logger("Testing the following URL -> " + url);
    // Call function to check enumeration using /wp-json/wp/v2/users endpoint
    var jsonAuthors = archiveJson(msg);

    // Call function to check enumeration using /?author={i} endpoint
    var archiveAuthors = userEnumerate(msg);

    // If any username(s) found
    if (jsonAuthors.length) {
        logger("Vulnerable to user enumeration.");
        var alertEvidence1 = "Found author(s) -> " + jsonAuthors.join(", ");
        // Raise alert
        raiseAlert(
            pluginid,
            3, // risk: 0: info, 1: low, 2: medium, 3: high
            3, // confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
            alertName,
            alertDesc,
            alertEvidence1,
            alertSol,
            alertReference,
            cweId,
            wascId,
            msg,
            url + "/wp-json/wp/v2/users"
        );
    }

    if (archiveAuthors.length) {
        logger("Vulnerable to user enumeration.");
        var alertEvidence = "Found author(s) -> ";
        for (var i in archiveAuthors) {
            alertEvidence += archiveAuthors[i].username + ", ";
        }
        url = url + "/?author=" + archiveAuthors[0].iterator;
        // Raise alert
        raiseAlert(
            pluginid,
            3, // risk: 0: info, 1: low, 2: medium, 3: high
            2, // confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
            alertName,
            alertDesc,
            alertEvidence,
            alertSol,
            alertReference,
            cweId,
            wascId,
            msg,
            url
        );
    }
    logger("Script run completed.");
}

function archiveJson(msg) {
    logger("Testing feed enumeration");
    var authors = [];
    var newReq = sendReq(msg, '/wp-json/wp/v2/users');
    var responseHeader = newReq.getResponseHeader();
    if (responseHeader.getStatusCode() === 200 && responseHeader.getHeader("Content-Type").contains('json')); {
        var responseBody = JSON.parse(newReq.getResponseBody().toString());
        logger("200 response with JSON");
        for (var i in responseBody) {
            authors.push(responseBody[i].slug); // Usernames (author names)
        }
    }
    return authors;
}

function userEnumerate(msg) {
    logger("Testing author enumeration");
    // Array to store found usernames
    var authors = [];
    // Initialise iterator
    var i = 1;
    // To iterate first 10 possible enumerations
    while (i && i < 10) {
        var newReq = sendReq(msg, i);
        // If enum possible, 301 status code is constant
        if (newReq.getResponseHeader().getStatusCode() === 301) {
            // Get the redirection location
            var redirect = newReq.getResponseHeader().getHeader("Location");
            // Extract username from Redirect Location
            try {
                var authorName = redirect.split("author/")[1].split("/")[0];
                var authorEntry = {
                    username: authorName,
                    iterator: i
                };
                authors.push(authorEntry);
                logger("Vulnerable Endpoint.");
                i++;
            } catch (err) {
                // If redirection but no username found
                if (err instanceof TypeError) {
                    logger("Endpoint not vulnerable.");
                    i++;
                }
            }
        } else {
            i++;
        }
    }
    return authors;
}

function sendReq(msg, query) {
    logger("Sending a request");
    var newReq = msg.cloneRequest();
    var uri = newReq.getRequestHeader().getURI();
    isNaN(query) ? uri.setPath(query) : uri.setQuery("author=" + query);
    logger("URL -> " + uri.toString());
    // Initialise the sender
    var sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
    // Send and Receive Request
    sender.sendAndReceive(newReq);
    // Debugging
    // logger("Request Header -> " + newReq.getRequestHeader().toString())
    // logger("Request Body -> " + newReq.getRequestBody().toString())
    // logger("Response Header -> " + newReq.getResponseHeader().toString())
    // logger("Raw Response Body -> " + newReq.getResponseBody().toString())
    return newReq;

}

/**
 * Raise an alert.
 * @see https://www.javadoc.io/doc/org.zaproxy/zap/latest/org/parosproxy/paros/core/scanner/Alert.html
 */
function raiseAlert(pluginid, alertRisk, alertConfidence, alertName, alertDesc, alertEvidence, alertSol, alertReference, cweId, wascId, msg, url) {
    var extensionAlert = extLoader.getExtension(ExtensionAlert.NAME);
    var ref = new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, msg);

    var alert = new Alert(pluginid, alertRisk, alertConfidence, alertName);
    alert.setDescription(alertDesc);
    alert.setEvidence(alertEvidence);
    alert.setSolution(alertSol);
    alert.setReference(alertReference);
    alert.setCweId(cweId);
    alert.setWascId(wascId);
    alert.setMessage(msg);
    alert.setUri(url);

    extensionAlert.alertFound(alert, ref);
}
