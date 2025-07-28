// Note that new active scripts will initially be disabled
// -------------------------------------------------------------------
// Swagger Secrets & Version Detector - ZAP Active Scan Rule Script
// -------------------------------------------------------------------
// Modern ZAP registration using getMetadata() function
// Import required ZAP Java types for modern registration

var URI = Java.type('org.apache.commons.httpclient.URI');
var ScanRuleMetadata = Java.type("org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata");
var CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");
function getMetadata() {
return ScanRuleMetadata.fromYaml(`
id: 100043
name: Swagger UI Secret & Vulnerability Detector
description: >
  Detects exposed Swagger UI and OpenAPI endpoints that leak sensitive secrets such as API keys, 
  OAuth client secrets, access tokens, or run vulnerable versions. This scanner performs comprehensive 
  detection of sensitive information disclosure in API documentation.
solution: >
  Remove hardcoded secrets from API documentation, restrict access to API documentation endpoints,
  and upgrade Swagger UI to a secure version. Ensure proper authentication is required to access documentation.
category: info_gather
risk: high
confidence: medium
cweId: 522  # Insufficiently Protected Credentials
alertTags:
  ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue()}
  ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue()}
status: alpha
codeLink: https://example.com/swagger-ui-detector.js
helpLink: https://www.example.com/
`);
}

// -------------------------------------------------------------------
// 1. List of commonly exposed Swagger/OpenAPI documentation paths
// -------------------------------------------------------------------
var SWAGGER_PATHS = [
    "/swagger", "/swagger/", "/swagger/index.html", "/swagger/ui", "/swagger/ui/",
    "/swagger/ui/index", "/swagger/ui/index.html", "/swagger-ui", "/swagger-ui/",
    "/swagger-ui/index.html", "/swagger-ui/index", "/docs", "/docs/",
    "/api-docs", "/v2/api-docs", "/v3/api-docs", "/swagger.json",
    "/swagger.yaml", "/openapi.json", "/openapi.yaml"
];

// -------------------------------------------------------------------
// 2. Regex matchers for path filtering (more flexible than exact matches)
// -------------------------------------------------------------------
var SWAGGER_REGEX_PATHS = [
    /\/swagger\/?$/i,
    /\/swagger\/index\.html$/i,
    /\/swagger\/ui\/?$/i,
    /\/swagger\/ui\/index(\.html)?$/i,
    /\/swagger-ui\/?$/i,
    /\/swagger-ui\/index(\.html)?$/i,
    /\/docs\/?$/i,
    /\/api-docs$/i,
    /\/v2\/api-docs$/i,
    /\/v3\/api-docs$/i,
    /\/swagger\.(json|yaml)$/i,
    /\/openapi\.(json|yaml)$/i,
    /\/api(\/v[0-9]+)?\/.*$/i,
    /\/v[0-9]+\/swagger.*$/i,
    /\/v[0-9]+\/openapi.*$/i,
    /\/nswag\/?$/i,
    /\/redoc\/?$/i,
    /\/admin\/?$/i, 
    /\/config(\.json|\.yaml|\.yml|\.php)?$/i,
    /\/debug(\.log|\.txt)?$/i,
    /\/\.env$/i, 
    /\/\.git\/config$/i, 
    /\/login\/?$/i, 
    /\/signin\/?$/i,
    /\/upload\/.*$/i, 
    /\/graphql$/i, 
    /\/graphiql$/i, 
    /\/phpinfo\.php$/i,
    /\/server-status$/i, 
    /\/actuator\/.*$/i, 
    /\/\.git\/HEAD$/i, 
    /\/backup\.zip$/i,
    /\/db\.sql$/i
];

// -------------------------------------------------------------------
// 3. Regex patterns to detect likely secrets in Swagger responses
// -------------------------------------------------------------------
var SECRET_REGEXES = [
    /["']?clientId["']?\s*:\s*["'](?!client_id|""|.{0,6}$).*?["']/gi,
    /["']?clientSecret["']?\s*:\s*["'](?!client_secret|""|.{0,6}$).*?["']/gi,
    /["']?oAuth2ClientId["']?\s*:\s*["'](?!client_id|""|.{0,6}$).*?["']/gi,
    /["']?oAuth2ClientSecret["']?\s*:\s*["'](?!client_secret|""|.{0,6}$).*?["']/gi,
    /["']?api_key["']?\s*:\s*["'](?!your_api_key_here|""|.{0,6}$).*?["']/gi,
    /["']?access_token["']?\s*:\s*["'](?!""|.{0,6}$).*?["']/gi,
    /["']?authorization["']?\s*:\s*["']Bearer\s+(?!""|.{0,6}$).*?["']/gi
];

// -------------------------------------------------------------------
// 4. Known dummy/test values that should be ignored
// -------------------------------------------------------------------
var FALSE_POSITIVES = [
    "clientid", "clientsecret", "string", "n/a", "null", "na", "true", "false",
    "value_here", "your_key", "your_api_key_here", "demo_token", "test1234",
    "dummysecret", "{token}", "bearer{token}", "placeholder", "insert_value"
];

// -------------------------------------------------------------------
// 5. False positive filter: heuristic to skip known dummy/test data
// -------------------------------------------------------------------
function isFalsePositiveKV(kvString) {
    if (!kvString || kvString.length < 1) return true;

    var kvMatch = kvString.match(/["']?([^"']+)["']?\s*:\s*["']?([^"']+)["']?/);
    if (!kvMatch || kvMatch.length < 3) return false;

    var key = kvMatch[1].toLowerCase().trim();
    var value = kvMatch[2].toLowerCase().trim();
    value = value.replace(/[\s"'{}]/g, '');

    if (value.length < 8) return true;

    var contextKeys = ["example", "description", "title", "note"];
    for (var i = 0; i < contextKeys.length; i++) {
        if (key.indexOf(contextKeys[i]) !== -1) return true;
    }

    var junkTokens = ["test", "sample", "dummy", "mock", "try", "placeholder", "your", "insert"];
    for (var i = 0; i < junkTokens.length; i++) {
        if (value.indexOf(junkTokens[i]) !== -1 || key.indexOf(junkTokens[i]) !== -1) return true;
    }

    for (var i = 0; i < FALSE_POSITIVES.length; i++) {
        if (value === FALSE_POSITIVES[i]) return true;
    }

    return false;
}

// -------------------------------------------------------------------
// 6. Redact secret values in evidence (show only first 5 chars)
// -------------------------------------------------------------------
function redactSecret(secret) {
    var parts = secret.split(':');
    if (parts.length < 2) return secret;
    var value = parts.slice(1).join(':').trim().replace(/^"|"$/g, '');
    return parts[0] + ': "' + value.substring(0, 5) + '..."';
}

// -------------------------------------------------------------------
// 7. Detect Swagger UI version in HTML/JS
// -------------------------------------------------------------------
function detectSwaggerVersion(body) {
    if (body.indexOf('SwaggerUIBundle') !== -1) return 3;
    if (body.indexOf('SwaggerUi') !== -1 || body.indexOf('window.swaggerUi') !== -1 || body.indexOf('swashbuckleConfig') !== -1) return 2;
    if (body.indexOf('NSwag') !== -1 || body.indexOf('nswagui') !== -1) return 4;
    return 0;
}

function extractVersion(body) {
    var versionRegex = /version\s*[:=]\s*["']?(\d+\.\d+\.\d+)["']?/i;
    var match = body.match(versionRegex);
    return match ? match[1] : null;
}

function versionToInt(v) {
    var parts = v.split(".");
    return (parseInt(parts[0], 10) * 10000) + (parseInt(parts[1], 10) * 100) + parseInt(parts[2], 10);
}

// -------------------------------------------------------------------
// 8. Main scan logic: runs once per node
// -------------------------------------------------------------------
function scanNode(as, msg) {
    var origUri = msg.getRequestHeader().getURI();
    var scheme = origUri.getScheme();
    var host = origUri.getHost();
    var port = origUri.getPort();
    var base = scheme + "://" + host + ((port !== -1 && port !== 80 && port !== 443) ? ":" + port : "");

    // --- Pass 1: Check static Swagger paths ---
    for (var i = 0; i < SWAGGER_PATHS.length; i++) {
        scanPath(as, msg, scheme, host, port, SWAGGER_PATHS[i], base + SWAGGER_PATHS[i]);
    }

    // --- Pass 2: Check current request path if it matches any regex ---
    var currentPath = origUri.getPath();
    for (var r = 0; r < SWAGGER_REGEX_PATHS.length; r++) {
        if (SWAGGER_REGEX_PATHS[r].test(currentPath)) {
            scanPath(as, msg, scheme, host, port, currentPath, base + currentPath);
        }
    }
}

// -------------------------------------------------------------------
// 9. Scan a single path (version + secret detection reused)
// -------------------------------------------------------------------
function scanPath(as, origMsg, scheme, host, port, pathOnly, fullPath) {
    var requestMsg = origMsg.cloneRequest();

    try {
        requestMsg.getRequestHeader().setMethod("GET");
        var newUri = new URI(scheme, null, host, port, pathOnly);
        requestMsg.getRequestHeader().setURI(newUri);
        requestMsg.getRequestHeader().setContentLength(0);

        var origHeaders = origMsg.getRequestHeader();
        ["User-Agent", "Cookie", "Authorization"].forEach(function (header) {
            var val = origHeaders.getHeader(header);
            if (val) requestMsg.getRequestHeader().setHeader(header, val);
        });

        as.sendAndReceive(requestMsg, false, false);
    } catch (err) {
        return;
    }

    var body = requestMsg.getResponseBody().toString();
    var version = detectSwaggerVersion(body);
    var semver = extractVersion(body);

    if (semver && (version === 2 || version === 3)) {
        var vInt = versionToInt(semver);
        if ((version === 2 && vInt < 20210) || (version === 3 && vInt < 32403)) {
            var cveReference = (version === 2)
                ? "https://nvd.nist.gov/vuln/detail/CVE-2019-17495"
                : "https://github.com/swagger-api/swagger-ui/releases/tag/v3.24.3";

            as.newAlert()
                .setRisk(3)
                .setConfidence(2)
                .setName("Vulnerable Swagger UI Version Detected (v" + semver + ")")
                .setAlertRef("100043-1")
                .setDescription("This Swagger UI version is known to contain vulnerabilities. Exploitation may allow unauthorized access, XSS, or token theft.\n\nAffected versions:\n- Swagger UI v2 < 2.2.10\n- Swagger UI v3 < 3.24.3")
                .setOtherInfo("Discovered at: " + fullPath)
                .setSolution("Upgrade to the latest version of Swagger UI. Regularly review and patch known issues.")
                .setReference(cveReference)
                .setMessage(requestMsg)
                .raise();
        }
    }

    detectSecrets(as, requestMsg, fullPath, body);
}

function detectSecrets(as, requestMsg, fullPath, body) {
    var matches = {};
    for (var j = 0; j < SECRET_REGEXES.length; j++) {
        var found = body.match(SECRET_REGEXES[j]);
        if (found) {
            for (var f = 0; f < found.length; f++) {
                var match = found[f];
                if (!isFalsePositiveKV(match)) {
                    matches[match] = true;
                }
            }
        }
    }

    var evidenceRaw = Object.keys(matches);
    var redactedEvidence = evidenceRaw.map(redactSecret);
   // var evidenceString = redactedEvidence.length > 0 ? redactedEvidence[0] : null;
    var foundClientId = evidenceRaw.some(e => /clientId/i.test(e));
    var foundSecret = evidenceRaw.some(e => /clientSecret|api_key|access_token|authorization/i.test(e));

    if (foundClientId && foundSecret) {
        as.newAlert()
            .setRisk(3)
            .setConfidence(2)
            .setName("Exposed Secrets in Swagger/OpenAPI Path")
            .setAlertRef("100043-2")
            .setDescription("Swagger UI endpoint exposes sensitive secrets such as client secrets, API keys, or OAuth tokens. These secrets may be accessible in the HTML source and should not be exposed publicly, as this can lead to compromise.")
            .setEvidence(redactedEvidence[0])
            .setOtherInfo("All secrets exposed:\n" + redactedEvidence.join("\n"))
            .setSolution("Remove hardcoded secrets from documentation and ensure the endpoint is protected with authentication.")
            .setReference("https://swagger.io/docs/open-source-tools/swagger-ui/usage/oauth2/")
            .setMessage(requestMsg)
            .raise();
    }
}