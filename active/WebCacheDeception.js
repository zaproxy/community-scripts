// Description: Detects and exploits Web Cache Deception vulnerabilities.
// Author: Eiliya Keshtkar (@e1l1ya)
// Version: 1.1
const ScanRuleMetadata = Java.type("org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata");
const Filename = 'customzap';
const DotSegment = "..%2f";

/** Delimiter/extension/path lists (populate according to threshold/strength) */
let Delimiters = [];
let Extensions = [];
let Folders = [];

// Most commonly working in real WCD cases
const DELIM_LOW = [
    "/",   // path confusion
    ";",   // matrix param (Apache/IIS quirks)
    ".",   // fake extension trigger
    "%2F"  // encoded slash bypass
];

// Frequently useful but less universal
const DELIM_MEDIUM = [
    "%2E", "%2e",   // encoded dot normalization issues
    "%3B",          // encoded semicolon
    "%2f",          // lowercase encoded slash
    "%5C", "\\",    // backslash (IIS / Windows)
    "%2E%2E",       // dot normalization
    "%3F"           // encoded question mark (path confusion cases)
];

// Rare but sometimes effective in proxy/CDN edge behavior
const DELIM_HIGH = [
    "#", "%23",
    "?", "%3F",
    "&", "%26",
    "=", "%3D",
    "+", "%2B",
    ",", "%2C",
    "%5F", "_",
    "%7C", "|"
];

// Very rare, parser edge cases, usually noisy
const DELIM_INSANE = [
    "!", "%21",
    "\"", "%22",
    "$", "%24",
    "%", "%25",
    "'", "%27",
    "(", "%28",
    ")", "%29",
    "*", "%2A",
    ":", "%3A",
    "<", "%3C",
    ">", "%3E",
    "@", "%40",
    "[", "%5B",
    "]", "%5D",
    "^", "%5E",
    "`", "%60",
    "{", "%7B",
    "}", "%7D",
    "~", "%7E",
    "-"
];

const EXT_LOW = ['css', 'js', 'min.js', 'png', 'jpg'];
const EXT_MEDIUM = ['jpeg', 'gif', 'svg', 'webp', 'ico', 'woff', 'woff2', 'pdf', 'mp4', 'bmp', 'tiff'];
const EXT_HIGH = ['tif', 'scss', 'sass', 'less', 'styl', 'jsx', 'xml', 'csv', 'html', 'htm'];
const EXT_INSANE = ['xhtml', 'psd', 'ts', 'tsx', 'coffee', 'ttf', 'otf', 'eot', 'webm', 'mp3', 'wav', 'm4a', 'txt', 'json'];

const FLD_LOW = [
    'static', 'assets', 'public', 'media', 'uploads', 'images', 'img', 'css', 'js',
];
const FLD_MEDIUM = [
    'fonts', 'video', 'videos', 'downloads', 'public/css', 'public/js', 'public/images',
    'icons', 'backgrounds', 'banners',
];
const FLD_HIGH = [
    'logo', 'javascript', 'scripts', 'styles', 'typefaces', 'audio',
    'music', 'podcast', 'stream', 'documents', 'docs', 'pdf', 'attachments', 'files',
    'themes', 'templates'
];
const FLD_INSANE = [
    'layouts', 'skins', 'design', 'lib', 'libs', 'library', 'libraries', 'dist', 'build', 'min',
    'node_modules', 'bower_components', 'vendor', 'vendor/assets', 'app/assets', 'storage/app/public',
    'wp-content/uploads', 'wp-content/themes', 'wp-content/plugins', 'wp-includes/js', 'wp-includes/css', 'sites/default/files', 'cache', 'resources'
];

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
id: 100046
name: Web Cache Deception Detection
description: >
  Detect Web Cache Deception in two ways: 1) add delimiters and a file with an extension, 2) combine the attack with path traversal.
solution: >
  1. Configure the cache to not cache responses with cookies or session tokens.
  2. Implement Cache-Control: private for authenticated pages.
  3. Validate file extensions and paths before allowing caching.
  4. Use the Vary: Cookie header appropriately.
references:
  - https://portswigger.net/web-security/web-cache-deception
  - https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Web_Cache_Deception
category: SERVER
risk: MEDIUM
confidence: MEDIUM
cweId: 524
wascId: 13
alertTags:
  OWASP_2021_A01: Broken Access Control
  CWE-524: Information Exposure Through Caching
  WASC-13: Information Leakage
status: alpha
alertRefOverrides:
  100046-1:
    name: Web Cache Deception - Extension/Delimiter
    description: >
      The server appears to cache sensitive pages when accessed with file extensions or crafted delimiters.
      This could allow attackers to cache sensitive user pages by appending file extensions or using delimiters,
      potentially exposing private data to other users.
  100046-2:
    name: Web Cache Deception - Path Traversal
    description: >
      The server appears vulnerable to web cache deception via path traversal technique.
      It may permit caching of sensitive resources due to improper path validation when traversing directories.
`);
}

function isStaticPath(path) {
    if (!path) return false;
    const staticExts = [
        "css", "js", "gif", "jpg", "jpeg", "png", "svg", "ico", "webp",
        "woff", "woff2", "ttf", "otf", "eot", "mp3", "wav", "m4a", "mp4",
        "webm", "flv", "mov", "avi", "wmv", "pdf", "bmp", "tiff", "psd"
    ];
    let lastPart = path.split("?")[0].split("#")[0];
    let dotSplit = lastPart.split(".");
    if (dotSplit.length < 2) return false;
    let ext = dotSplit[dotSplit.length - 1].toLowerCase();
    return staticExts.includes(ext);
}

function configureScanInputs(as) {
    Delimiters = [].concat(DELIM_LOW);
    Extensions = [].concat(EXT_LOW);
    Folders = [].concat(FLD_LOW);
    let strength = as.getAttackStrength();

    if (strength == "MEDIUM") {
        Delimiters = Delimiters.concat(DELIM_MEDIUM);
        Extensions = Extensions.concat(EXT_MEDIUM);
        Folders = Folders.concat(FLD_MEDIUM);
    }
    if (strength == "HIGH") {
        Delimiters = Delimiters.concat(DELIM_HIGH);
        Extensions = Extensions.concat(EXT_HIGH);
        Folders = Folders.concat(FLD_HIGH);
    }
    if (strength == "INSANE") {
        Delimiters = Delimiters.concat(DELIM_INSANE);
        Extensions = Extensions.concat(EXT_INSANE);
        Folders = Folders.concat(FLD_INSANE);
    }
}

/**
 * Extracts caching status indicators from common response headers
 */
function getCacheStatus(msg) {
    let headers = msg.getResponseHeader();
    let xCache = headers.getHeader("X-Cache");
    let cfCache = headers.getHeader("CF-Cache-Status");
    let age = headers.getHeader("Age");
    
    let combined = "";
    if (xCache !== null) combined += " X-CACHE:" + xCache;
    if (cfCache !== null) combined += " CF-CACHE:" + cfCache;
    if (age !== null) combined += " AGE:" + age;

    return combined.toUpperCase();
}

/**
 * Validates whether the crafted request was genuinely stored/served from cache
 */
function findEvidence(as, msg) {
    let threshold = as.getAlertThreshold();
    let cacheStatus1 = getCacheStatus(msg);

    // LOW: Alert on any indicative caching headers present
    if (threshold == "LOW") {
        return cacheStatus1.length > 0;
    }

    // MEDIUM / HIGH: Repeat request to verify state transition (e.g., MISS -> HIT or non-zero Age)
    let repeatMsg = msg.cloneRequest();
    as.sendAndReceive(repeatMsg, false, false);
    
    let cacheStatus2 = getCacheStatus(repeatMsg);
    let age2 = repeatMsg.getResponseHeader().getHeader("Age");

    // Standard HIT indicator in repeat response
    if (cacheStatus2.indexOf("HIT") !== -1) {
        return true;
    }

    // Age header growing indicates proxy serving from cache
    if (age2 !== null && parseInt(age2, 10) > 0) {
        return true;
    }

    return false;
}

function scanNode(as, msg) {
    configureScanInputs(as);
    let endWithSlash = false;
    let orgPath = msg.getRequestHeader().getURI().getPath();

    if (orgPath !== null && isStaticPath(orgPath)) {
        return;
    }

    if (orgPath === null) {
        orgPath = "";
    }
    if (orgPath == "/") {
        endWithSlash = true;
    }

    let isVulnerable = additionalFile2Cache(as, msg, orgPath, endWithSlash);
    if (!isVulnerable && (as.getAttackStrength() == "HIGH" || as.getAttackStrength() == "INSANE")) {
        pathTraversal2Cache(as, msg, orgPath, endWithSlash);
    }
}

function encodeIfNeeded(delim) {
    if (/^%[0-9A-Fa-f]{2}$/.test(delim)) {
        return delim.toUpperCase();
    }
    const SAFE_RAW = ["/", ".", ";"];
    if (SAFE_RAW.indexOf(delim) !== -1) {
        return delim;
    }
    return encodeURIComponent(delim);
}

function additionalFile2Cache(as, msg, orgPath, endWithSlash) {
    for (let i = 0; i < Delimiters.length; i++) {
        let currentDelimiters = Delimiters[i];
        for (let j = 0; j < Extensions.length; j++) {
            let currentExtension = Extensions[j];
            let newMsg = msg.cloneRequest();
            let payload, newPath;
            let uri = newMsg.getRequestHeader().getURI();

            let safeDelim = encodeIfNeeded(currentDelimiters);

            if (endWithSlash && currentDelimiters === "/") {
                payload = Filename + "." + currentExtension;
            } else {
                payload = safeDelim + Filename + "." + currentExtension;
            }
            newPath = orgPath + payload;

            if (as.isStop()) {
                return false;
            }

            uri.setPath(newPath);
            as.sendAndReceive(newMsg, false, false);

            let statusCode = newMsg.getResponseHeader().getStatusCode();
            if (statusCode >= 200 && statusCode < 300 && findEvidence(as, newMsg)) {
                raiseAlert(as, "100046-1", payload, newMsg, newPath);
                return true;
            }
        }
    }
    return false;
}

function pathTraversal2Cache(as, msg, orgPath, endWithSlash) {
    let pathDepth = orgPath.split('/').length - 1;
    let parentDir = "";
    for (let j = 0; j < pathDepth; j++) {
        parentDir += DotSegment;
    }
    for (let i = 0; i < Folders.length; i++) {
        let currentFolder = Folders[i];
        if (as.isStop()) {
            return;
        }
        let payload = "/" + currentFolder + "/" + parentDir;
        let newPath = payload + orgPath;
        let newMsg = msg.cloneRequest();

        newMsg.getRequestHeader().getURI().setEscapedPath(newPath);
        as.sendAndReceive(newMsg, false, false);

        let statusCode = newMsg.getResponseHeader().getStatusCode();
        if (statusCode >= 200 && statusCode < 300 && findEvidence(as, newMsg)) {
            raiseAlert(as, "100046-2", payload, newMsg, newPath);
            return;
        }
    }
}

function raiseAlert(as, alertRef, payload, newMsg, newPath) {
    let requestUri = newMsg.getRequestHeader().getURI().toString();

    as.newAlert(alertRef)
        .setUri(requestUri)
        .setParam("Path")
        .setAttack(newPath)
        .setEvidence(payload)
        .setMessage(newMsg)
        .raise();
}

function scanHost(as, msg) { }
function scan(as, msg, param, value) { }