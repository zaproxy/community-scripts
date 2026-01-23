/**
 * Contributed by Eiliya Keshtkar (https://www.hackmelocal.com/)
 * @author Eiliya Keshtkar <eiliyakeshtkar0@gmail.com>
 */
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
var URI = Java.type("org.apache.commons.httpclient.URI");
var Model = Java.type("org.parosproxy.paros.model.Model");

// === Helper: Pretty Divider ===
function divider(label) {
    print("\n" + "-".repeat(60));
    if (label) print("Target: " + label);
    print("-".repeat(60));
}

// === Helper: Send GET Request with Original Headers ===
function sendGetWithOriginalHeaders(originalReqHeader, url) {
    try {
        var uri = new URI(url, true);
        var msg = new HttpMessage();
        msg.getRequestHeader().setMethod("GET");
        msg.getRequestHeader().setURI(uri);

        // Copy all request headers except Host & Content-Length
        var origHeaders = originalReqHeader.getHeaders();
        for (var i = 0; i < origHeaders.size(); i++) {
            var h = origHeaders.get(i);
            var name = h.getName();
            var value = h.getValue();
            if (!name.equalsIgnoreCase("Host") && !name.equalsIgnoreCase("Content-Length")) {
                msg.getRequestHeader().setHeader(name, value);
            }
        }

        // Set Host header properly
        var host = uri.getHost();
        var port = uri.getPort();
        msg.getRequestHeader().setHeader("Host", port > 0 && port !== 80 && port !== 443 ? host + ":" + port : host);

        // Send it as manual request ( this will show in history )
        var sender = new HttpSender(
            Model.getSingleton().getOptionsParam().getConnectionParam(),
            true,
            HttpSender.MANUAL_REQUEST_INITIATOR
        );
        sender.sendAndReceive(msg, true);
        return msg;
    } catch (e) {
        print("[!] Error sending to: " + url + " => " + e);
        return null;
    }
}

// === Main ===
function invokeWith(msg) {
    var baseUrl = msg.getRequestHeader().getURI().toString();
    if (!baseUrl || baseUrl.trim() === "") return;

    divider(baseUrl);

    var originalBody = msg.getResponseBody().toString();
    var delimiters = [";", "%00", "%0A", "%09", ".", "/", "~"];
    var exts = [
        "css","js","jpg","png","gif","svg","webp","pdf","zip","docx","xlsx","mp3","mp4","ttf","woff","woff2","svgz"
    ];
    var filename = "cachetest";

    print("[+] Starting Web Cache Deception tests...");
    print("[i] Base: " + baseUrl + "\n");

    // === Standard Delimiter + Extension tests ===
    for (var i = 0; i < delimiters.length; i++) {
        var d = delimiters[i];
        var probeUrl = baseUrl + d + filename;
        var probeMsg = sendGetWithOriginalHeaders(msg.getRequestHeader(), probeUrl);
        if (!probeMsg) continue;

        var status = probeMsg.getResponseHeader().getStatusCode();
        if (status !== 200) continue;

        print("\n[*] Delimiter accepted: '" + d + "'");
        print("    Baseline probe: " + probeUrl + " | Status: " + status);

        for (var j = 0; j < exts.length; j++) {
            var ext = exts[j];
            var testUrl = baseUrl + d + filename + "." + ext;
            var newMsg = sendGetWithOriginalHeaders(msg.getRequestHeader(), testUrl);
            if (!newMsg) continue;

            var code = newMsg.getResponseHeader().getStatusCode();
            if (code !== 200) continue;

            var xCache = null;
            var hdrs = newMsg.getResponseHeader().getHeaders();
            for (var h = 0; h < hdrs.size(); h++) {
                var hh = hdrs.get(h);
                if (hh.getName().equalsIgnoreCase("X-Cache")) {
                    xCache = hh.getValue();
                    break;
                }
            }

            var testBody = newMsg.getResponseBody().toString();
            var bodySame = (testBody === originalBody);
            print("    [+] Payload: " + testUrl);
            print("        Status: " + code +
                (xCache ? " | X-Cache: " + xCache : " | no X-Cache") +
                (bodySame ? " | SAME_BODY" : ""));
            
            if (xCache && xCache.toLowerCase().includes("hit") && bodySame) {
                print("        [!] Potential Cache Deception detected!");
            }
        }
    }

    // === Traversal-style encoded payload tests ===
    try {
        var urlObj = new java.net.URL(baseUrl);
        var origin = urlObj.getProtocol() + "://" + urlObj.getHost();
        if (urlObj.getPort() > 0) origin += ":" + urlObj.getPort();
        var path = urlObj.getPath();

        var folders = ["static", "assets", "resources", "js", "css", "uploads", "files", "cdn"];
        var encoders = [
            "%23%2f..%2f", // #/../
            "%23%2F..%2F", // uppercase
            "%2e%2e%2f",   // ../
            "..%2f"        // simple
        ];

        print("\n[+] Testing encoded traversal-style payloads...\n");

        for (var f = 0; f < folders.length; f++) {
            for (var e = 0; e < encoders.length; e++) {
                var folder = folders[f];
                var encoder = encoders[e];
                var testUrl = origin + path + encoder + folder;
                var tMsg = sendGetWithOriginalHeaders(msg.getRequestHeader(), testUrl);
                if (!tMsg) continue;

                var code = tMsg.getResponseHeader().getStatusCode();
                if (code !== 200) continue;

                var hdrs = tMsg.getResponseHeader().getHeaders();
                var xCache = null;
                for (var h = 0; h < hdrs.size(); h++) {
                    var hh = hdrs.get(h);
                    if (hh.getName().equalsIgnoreCase("X-Cache")) {
                        xCache = hh.getValue();
                        break;
                    }
                }

                var testBody = tMsg.getResponseBody().toString();
                var bodySame = (testBody === originalBody);

                print("    [+] Traversal Payload: " + testUrl +
                      " | Status: " + code +
                      (xCache ? " | X-Cache: " + xCache : " | no X-Cache") +
                      (bodySame ? " | SAME_BODY" : ""));

                if (xCache && xCache.toLowerCase().includes("hit") && bodySame) {
                    print("        [!] Potential Cache Deception via encoded traversal!");
                }
            }
        }

// === Semicolon traversal and encoded path confusion tests ===
print("\n[+] Testing semicolon and encoded path confusion payloads...\n");

try {
    var sensitiveFiles = [
        "robots.txt", "sitemap.xml", "index.html", "index.php",
        "login", "admin", "config", "api", "dashboard"
    ];

    for (var s = 0; s < sensitiveFiles.length; s++) {
        var sf = sensitiveFiles[s];
        var testUrl = baseUrl + ";%2f%2e%2e%2f" + sf + "?test";

        var tMsg = sendGetWithOriginalHeaders(msg.getRequestHeader(), testUrl);
        if (!tMsg) continue;

        var code = tMsg.getResponseHeader().getStatusCode();
        if (code !== 200) continue;

        var hdrs = tMsg.getResponseHeader().getHeaders();
        var xCache = null;
        for (var h = 0; h < hdrs.size(); h++) {
            var hh = hdrs.get(h);
            if (hh.getName().equalsIgnoreCase("X-Cache")) {
                xCache = hh.getValue();
                break;
            }
        }

        var testBody = tMsg.getResponseBody().toString();
        var bodySame = (testBody === originalBody);

        print("    [+] Semicolon Payload: " + testUrl +
              " | Status: " + code +
              (xCache ? " | X-Cache: " + xCache : " | no X-Cache") +
              (bodySame ? " | SAME_BODY" : ""));

        if (xCache && xCache.toLowerCase().includes("hit") && bodySame) {
            print("        [!] Potential Cache Deception via semicolon traversal!");
        }
    }
} catch (e) {
    print("[!] Semicolon traversal error: " + e);
}


        // === Folder-prefixed traversal tests ===
        print("\n[+] Testing folder-prefixed traversal payloads...\n");
        for (var f = 0; f < folders.length; f++) {
            var folder = folders[f];
            var testUrl = origin + "/" + folder + "/..%2f" + path + "?";
            var tMsg = sendGetWithOriginalHeaders(msg.getRequestHeader(), testUrl);
            if (!tMsg) continue;

            var code = tMsg.getResponseHeader().getStatusCode();
            if (code !== 200) continue;

            var hdrs = tMsg.getResponseHeader().getHeaders();
            var xCache = null;
            for (var h = 0; h < hdrs.size(); h++) {
                var hh = hdrs.get(h);
                if (hh.getName().equalsIgnoreCase("X-Cache")) {
                    xCache = hh.getValue();
                    break;
                }
            }

            var testBody = tMsg.getResponseBody().toString();
            var bodySame = (testBody === originalBody);

            print("    " +
                  (xCache ? "[X]" : "[!]") + 
                  " Prefix Payload: " + testUrl +
                  " | Status: " + code +
                  (xCache ? " | X-Cache: " + xCache : " | no X-Cache") +
                  (bodySame ? " | SAME_BODY" : ""));

            if (xCache && xCache.toLowerCase().includes("hit") && bodySame) {
                print("        [!] Potential Cache Deception via folder prefix traversal!");
            }
        }

    } catch (e) {
        print("[!] Traversal error: " + e);
    }

    
    divider();
}
