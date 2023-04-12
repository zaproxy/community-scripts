/**
 * Contributed by Astra Security (https://www.getastra.com/)
 * @author Prince Mendiratta <prince.mendiratta@getastra.com>
 */
var pluginid = 100031;
var providerAddress = "dns.google";

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
 * Check for SPF / DMARC policies on a website.
 * 
 * A function which will be invoked against a specific "targeted" message.
 * 
 * @param msg - the HTTP message being acted upon. This is an HttpMessage object.
 */
function invokeWith(msg) {

    var url = msg.getRequestHeader().getURI().toString();
    // To check if script is running
    logger("Testing script against URL - " + url);

    // Regex to detect DMARC / SPF records
    var spfRegex = /^v=spf1.*/g;
    var dmarcRegex = /^v=DMARC1.*/g;

    testForPolicy(msg, "SPF", spfRegex, url);
    testForPolicy(msg, "DMARC", dmarcRegex, url);

    logger("Script run completed successfully.");
}

/**
 * Function that tests if a policy has been configured
 * @param {Object.<HttpMessage>} msg    - The HttpMessage Object being scanned
 * @param {String} policy               - The policy name
 * @param {RegExp} policyRegex          - The regex expression for detecting the policy
 * @param {String} url                  - The URL against which script has been invoked
 */
function testForPolicy(msg, policy, policyRegex, url) {
    var newReq = msg.cloneRequest();
    // Fetch TXT DNS records for root domain
    var fetchedTxtRecords = fetchRecords(newReq, policy);
    logger("Checking for presence of " + policy + " records.");
    checkIfPolicy(fetchedTxtRecords, policyRegex, policy, url, newReq);
}

/**
 * Checks if a specific DNS TXT record policy exists or not,
 * Raises an alert if the policy is not present
 * 
 * @param {Object.object} txtRecords	- The fetched DNS Records response
 * @param {RegExp} policyRegex 			- The regex expression for detecting the policy
 * @param {String} policyName 			- The policy name
 * @param {String} metaData 			- The extra meta data that will be sent in otherInfo field
 * @param {Object.<HttpMessage>} msg 	- The HttpMessage Object being scanned
 */
function checkIfPolicy(txtRecords, policyRegex, policyName, url, msg) {

    var cweId = 290;
    var wascId = 12;
    // All TXT records are under the "Answer" key in the response object
    var foundPolicy = checkForPolicy(txtRecords["Answer"], policyRegex);

    if (foundPolicy !== true) {
        var alertName = policyName + " Records not configured";
        var alertSol = policyName + " Records should be configured properly on domain to prevent email spoofing. ";
        var alertDesc = "Phishing and email spam are the biggest opportunities for hackers to enter the network. " +
            "If a single user clicks on some malicious email attachment, it can compromise an entire enterprise with ransomware, " +
            "cryptojacking scripts, data leakages or privilege escalation exploits. This can be prevented with the help of " +
            policyName + " records.";
        raiseAlert(
            pluginid,
            2, // risk:       0: info, 1: low, 2: medium, 3: high
            3, // confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
            alertName,
            alertDesc,
            alertSol,
            cweId,
            wascId,
            msg,
            url
        );
    }
}

/**
 * Function to fetch DNS TXT records over DoH
 * @param {Object.<HttpMessage>} msg - The HttpMessage Object being scanned
 * @param {String} policy 			 - The policy name to fetch records for.
 * @return {Object.object}			 - The fetched records.
 */
function fetchRecords(msg, policy) {
    var domain = msg.getRequestHeader().getURI().getHost();
    if (domain.startsWith("www")) {
        domain = domain.replace("www.", "");
    }
    if (policy === "DMARC") {
        domain = "_dmarc." + domain;
    }
    var path = "/resolve?name=" + domain + "&type=TXT";
    var targetUri = "https://" + providerAddress + path;
    var requestUri = new URI(targetUri, false);
    msg.getRequestHeader().setURI(requestUri);
    logger("Fetching TXT records for domain - " + domain);

    var sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
    sender.sendAndReceive(msg);
    // Debugging
    // logger("Request Header -> " + msg.getRequestHeader().toString())
    // logger("Request Body -> " + msg.getRequestBody().toString())
    // logger("Response Header -> " + msg.getResponseHeader().toString())
    // logger("Response Body -> " + msg.getResponseBody().toString())

    var fetchedTxtRecords = JSON.parse(msg.getResponseBody().toString());
    return fetchedTxtRecords;
}

/**
 * Function to check for a policy in TXT records
 * @param {Object.object} txtRecords - The fetched DNS Records response to test regex against
 * @param {RegExp} policyRegex 		 - The regex expression for detecting the policy
 * @returns {boolean}				 - Return true if found record
 */
function checkForPolicy(txtRecords, policyRegex) {
    if (txtRecords === undefined) {
        logger("No TXT records found for the domain.");
        return false;
    }
    for (var txtRecord in txtRecords) {
        if (policyRegex.test(txtRecords[txtRecord]["data"])) {
            return true;
        }
    }
    return false;
}

/**
 * Raise an alert.
 * @see https://www.javadoc.io/doc/org.zaproxy/zap/latest/org/parosproxy/paros/core/scanner/Alert.html
 */
function raiseAlert(pluginid, alertRisk, alertConfidence, alertName, alertDesc, alertSol, cweId, wascId, msg, url) {
    var extensionAlert = extLoader.getExtension(ExtensionAlert.NAME);
    var ref = new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, msg);

    var alert = new Alert(pluginid, alertRisk, alertConfidence, alertName);
    alert.setDescription(alertDesc);
    alert.setSolution(alertSol);
    alert.setCweId(cweId);
    alert.setWascId(wascId);
    alert.setMessage(msg);
    alert.setUri(url);

    extensionAlert.alertFound(alert, ref);
}
