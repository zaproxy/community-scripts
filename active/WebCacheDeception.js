// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

const ScanRuleMetadata = Java.type("org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata");
const Filename = 'customzap';

const Delimiters = [
    "/",
    ";",
    ".",
    "?",
    "&",
    "=",
    "#",
    "+",
    ",",
    "|"
];

// File extensions that CDNs cache
const Extensions = [
    // Images
    "jpg", "jpeg", "png", "gif", "svg", "webp", "bmp", "ico",
    "tiff", "tif", "psd", "ai", "eps",

    // Styles
    "css", "scss", "sass", "less", "styl",

    // JavaScript
    "js", "jsx", "ts", "tsx", "coffee", "min.js",

    // Fonts
    "woff", "woff2", "ttf", "otf", "eot",

    // Media
    "mp4", "webm", "ogg", "mov", "avi", "wmv",
    "mp3", "wav", "ogg", "m4a", "flac",

    // Documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "rtf", "csv", "xml", "json",

    // Archives
    "zip", "tar", "gz", "rar", "7z", "iso",

    // Web files
    "html", "htm", "xhtml", "swf", "flv"
];

const Folders = [
    "static",
    "assets",
    "public",
    "media",
    "uploads",
    "images",
    "img",
    "icons",
    "logo",
    "banners",
    "backgrounds",
    "js",
    "javascript",
    "scripts",
    "css",
    "styles",
    "fonts",
    "webfonts",
    "typefaces",
    "video",
    "videos",
    "mp4",
    "audio",
    "music",
    "podcast",
    "stream",
    "downloads",
    "documents",
    "pdf",
    "docs",
    "attachments",
    "resources",
    "files",
    "themes",
    "templates",
    "layouts",
    "skins",
    "design",
    "lib",
    "libs",
    "library",
    "libraries",
    "vendor",
    "node_modules",
    "bower_components",
    "dist",
    "build",
    "min",
    "wp-content/uploads",
    "wp-content/themes",
    "wp-content/plugins",
    "wp-includes/js",
    "wp-includes/css",
    "sites/default/files",
    "cache",
    "public/css",
    "public/js",
    "public/images",
    "storage/app/public",
    "app/assets",
    "vendor/assets",
];

var DotSegment = "..%2f";

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
id: 12345
name: Web Cache Deception Detection
description: Detect Web Cache Deception in 2 way 1. add delimiters and file with extention, 2. bind attack with path traversal
solution: Update the Web Cache policy to dont cache sensitive pages
references:
  - https://portswigger.net/web-security/web-cache-deception
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Web_Cache_Deception
category: SERVER
risk: MEDIUM
confidence: LOW
cweId: 524
wascId: 13
alertTags:
  OWASP_2021_A01: Broken Access Control
  CWE-524: Information Exposure Through Caching
  WASC-13: Information Leakage
status: alpha
alertRefOverrides:
  12345-1: {}
  12345-2:
    name: Active Vulnerability - Type XYZ
    description: Detect Web Cache Deception
`);
}

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ActiveScriptHelper object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanNode(as, msg) {
    var endWithSlash = false;
    var isVulnerable = false;

    // Skip cache deception testing for static files to reduce false positives and save resources
    // Static files (images, CSS, JavaScript) are normally cached by design, not a vulnerability
    // If Content-Type indicates static content, exit the function early
    var contentType = msg.getResponseHeader().getHeader("Content-Type");
    if (contentType !== null && (contentType.includes("image/") || contentType.includes("text/css") || contentType.includes("application/javascript"))) return;

    // Get the original path from the request URI
    var orgPath = msg.getRequestHeader().getURI().getPath();

    // Handle null path - convert to empty string for consistent processing
    if (orgPath === null) {
        orgPath = ""
    }

    // Normalize the path by removing trailing slash (if present)
    // Exceptions: Don't modify root path "/" and skip if path is already null
    if (orgPath !== null && orgPath.endsWith("/")) {
        endWithSlash = true;
    }

    isVulnerable = additionalFile2Cache(as, msg, orgPath, endWithSlash);

    if (!isVulnerable) {
        pathTraversal2Cache(as, msg, orgPath, endWithSlash);
    }

    // Path traversal to cache
    return;
}

function additionalFile2Cache(as, msg, orgPath, endWithSlash) {

    // Add additional file
    for (let i = 0; i < Delimiters.length; i++) {
        var currentDelimiters = Delimiters[i];

        for (let j = 0; j < Extensions.length; j++) {
            var newMsg = msg.cloneRequest();
            var currentExtention = Extensions[j];

            if (endWithSlash && currentDelimiters == "/") {
                var payload = Filename + "." + currentExtention;
            }
            else {
                var payload = currentDelimiters + "/" + Filename + "." + currentExtention;
            }

            var newPath = orgPath + payload;

            // Check if the scan was stopped before performing lengthy tasks
            if (as.isStop()) {
                return
            }

            newMsg.getRequestHeader().getURI().setPath(newPath);

            // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
            as.sendAndReceive(newMsg, false, false);

            // Check has X Cache header
            var hasXCache = newMsg.getResponseHeader().getHeader("X-Cache");
            var statusCode = newMsg.getResponseHeader().getStatusCode();
            if (hasXCache !== null && statusCode >= 200 && statusCode <= 300) {

                raiseAlert(as, payload, newMsg, newPath)
                return;
            }
        }
    }
    return ;

}

function pathTraversal2Cache(as, msg, orgPath, endWithSlash) {
    var pathDepth = orgPath.split('/').length - 1;
    var parentDir = "";
    var newPath = "";
    var newMsg = msg.cloneRequest();

    // Count Path Depth
    for (var j = 0; j < pathDepth; j++) {
        parentDir += DotSegment;
    }

    for (let i = 0; i < Folders.length; i++) {
        var currentFolder = Folders[i];

        // Check if the scan was stopped before performing lengthy tasks
        if (as.isStop()) {
            return
        }

        payload = "/" + currentFolder + "/" + parentDir;
        newPath =  payload + orgPath;

        newMsg.getRequestHeader().getURI().setEscapedPath(newPath);

        as.sendAndReceive(newMsg, false, false);

        // Check has X Cache header
        var hasXCache = newMsg.getResponseHeader().getHeader("X-Cache");
        var statusCode = newMsg.getResponseHeader().getStatusCode();
        if (hasXCache !== null && statusCode >= 200 && statusCode <= 300) {
            raiseAlert(as, payload, newMsg, newPath)
            return;
        }
    }
    return ;
}

function raiseAlert(as, payload, newMsg, newPath) {
    var requestUri = newMsg.getRequestHeader().getURI().toString();

    as.newAlert("12345-1")
        .setRisk(2)  // Medium
        .setConfidence(2)  // Medium
        .setName("Web Cache Deception Vulnerability Detected")
        .setDescription(
            "The server appears to cache sensitive pages when accessed with file extensions. " +
            "When requesting '" + newPath + "'." +
            "This could allow attackers to cache sensitive user pages by appending file extensions, " +
            "potentially exposing private data to other users."
        )
        .setUri(requestUri)
        .setParam("Path")
        .setAttack(newPath)
        .setEvidence(payload)
        .setSolution(
            "1. Configure the cache to not cache responses with cookies or session tokens\n" +
            "2. Implement cache-control: private for authenticated pages\n" +
            "3. Validate file extensions before allowing caching\n" +
            "4. Use Vary: Cookie header appropriately"
        )
        .setReference(
            "https://portswigger.net/web-security/web-cache-deception\n" +
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Web_Cache_Deception"
        )
        .setCweId(524)  // Information Exposure Through Caching
        .setWascId(13)  // Information Leakage
        .setMessage(newMsg)
        .raise();
}

/**
 * Scans a host.
 * The scanHost function will be called once per host being scanned.
 * @param as - the ActiveScan parent object that will do all the core interface tasks
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ActiveScriptHelper object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanHost(as, msg) {
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ActiveScriptHelper object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
}

