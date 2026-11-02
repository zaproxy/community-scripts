const PluginPassiveScanner = Java.type(
  "org.zaproxy.zap.extension.pscan.PluginPassiveScanner"
);
const ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);
const CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100044
name: Credential Exposure Detector (Passive)
description: >
  Detects exposed credentials (API keys, client secrets, OAuth tokens) in HTTP responses,
  request URL paths, and URL parameters. This includes Swagger/OpenAPI JSON, HTML pages,
  and other content types. The rule also scans URL paths and query parameters for credentials
  that may be unintentionally exposed through GET requests or misconfigured endpoints.
  This comprehensive approach helps identify secrets that may be exposed due to 
  misconfiguration or insecure deployment practices.

solution: >
  Remove hardcoded secrets from HTTP responses, URL paths, and URL parameters. Ensure 
  sensitive documentation (e.g., Swagger/OpenAPI) is not publicly accessible. Never include 
  credentials in URL paths or query parameters as they are visible in server logs, browser 
  history, and referrer headers. Use secret scanning tools in CI/CD pipelines, enforce 
  authentication for sensitive endpoints, implement access controls to prevent unauthorized 
  exposure, and use secure authentication mechanisms such as Authorization headers or 
  secure cookies over HTTPS.

references:
  - https://owasp.org/www-project-non-human-identities-top-10/2025/2-secret-leakage/
  - https://cwe.mitre.org/data/definitions/200.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
  - https://github.com/gitleaks/gitleaks

risk: HIGH
confidence: MEDIUM
cweId: 200
wascId: 13
alertTags:
  ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue()}
  ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue()}

otherInfo: >
  This rule uses pattern matching to detect hardcoded secrets such as API keys, OAuth tokens,
  cloud credentials, and session identifiers in HTTP responses, request URL paths, and URL 
  parameters. It includes regexes for JWTs, GitHub/NPM tokens, Azure/GCP keys, and more. 
  False positives are filtered using context-aware heuristics and known placeholder values. 
  Ideal for identifying credential leakage in API documentation, debug pages, misconfigured 
  endpoints, and insecure URL-based authentication schemes.
`);
}

var SECRET_REGEXES = [
  // JWTs
  // Standard JWT: header.payload.signature (3-part, base64url)
  {
    regex: /\b([A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g,
    type: "JWT Token",
    severity: "LOW",
  },

  // Extended JWTs (4–5 parts, e.g. JWE or chained tokens)
  {
    regex:
      /\b([A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}(?:\.[A-Za-z0-9_-]{16,}){1,2})\b/g,
    type: "Extended JWT",
    severity: "MEDIUM",
  },

  // ===== Core & vendor =====
  {
    regex: /\$?ANSIBLE[_\s-]?VAULT\b/i,
    type: "Ansible Vault",
    severity: "HIGH",
  },
  {
    regex: /x-(amz|goog)-(credential|security-token)/i,
    type: "Cloud Auth Header",
    severity: "HIGH",
  },
  // ===== Session / Auth tokens =====
  {
    regex:
      /\b(FedAuth|OpenIdConnect\.token\.v\d+|ssoCookie|auth[_]?key|authtoken|challengetoken|guestaccesstoken|prooftoken|redeem|tempauth|Auth(entication)?Cookie)=/i,
    type: "Session/Auth Token",
    severity: "HIGH",
  },

  // ===== Azure identifiers =====
  {
    regex: /((Tenant(.?id)?|\Wtid).{0,25}|login\.microsoftonline\.com)/i,
    type: "Azure Tenant ID",
    severity: "LOW",
  },
  // ===== Azure tokens/keys =====
  {
    regex:
      /([0-9A-Za-z]{33}AzCa[A-P][0-9A-Za-z]{5}=)|([0-9A-Za-z]{44}AzCa[0-9A-Za-z]{5}[AQgw])/i,
    type: "Azure Access Token",
    severity: "HIGH",
  },
  {
    regex: /[a-z0-9]{42}AzSe[a-z0-9]{6}/i,
    type: "Azure Storage Key",
    severity: "HIGH",
  },

  // ===== GitHub / NPM / HF =====
  {
    regex: /\b(gh[pousr]_[A-Za-z0-9]{36})\b/g,
    type: "GitHub Token",
    severity: "HIGH",
  },
  {
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
    type: "GitHub Fine-grained Token",
    severity: "HIGH",
  },
  { regex: /\bnpm_[a-z0-9]{30}\w{6}\b/i, type: "NPM Token", severity: "HIGH" },
  {
    regex: /\bhf_[A-Za-z0-9]{30,64}\b/i,
    type: "HuggingFace Token",
    severity: "HIGH",
  },
  // ===== Slack / SAML =====
  { regex: /:SAML:[12]\.0:cm:/i, type: "SAML Credential", severity: "HIGH" },
  {
    regex: /\Wxox[pbarose]-[a-z0-9]{10,}/i,
    type: "Slack Token",
    severity: "HIGH",
  },
  // ===== Generic Authorization / OAuth =====
  {
    regex: /["']?access_token["']?\s*[:=]\s*["']?/i,
    type: "Access Token",
    severity: "MEDIUM",
  },
  {
    // Matches JSON or YAML style: clientSecret: "value"
    regex:
      /["']?clientSecret["']?\s*:\s*["'](?!client_secret|""|.{0,6}$).*?["']/gi,
    type: "Client Secret",
    severity: "HIGH",
  },

  {
    regex: /["']?api_key["']?\s*[:=]\s*["']?/i,
    type: "API Key",
    severity: "HIGH",
  },

  {
    regex: /authorization\s*[:=]\s*([A-Za-z0-9_\-:\s=+\/]{10,200})/i,
    type: "Authorization Header",
    severity: "HIGH",
  },

  {
    regex: /\bclientId\b\s*:\s*["']([A-Fa-f0-9-]{36})["']/i,
    type: "OAuth Client ID",
    severity: "LOW",
  },
  {
    regex: /["']?oAuth2ClientId["']?\s*:\s*["']([A-Za-z0-9_\-]{1,50})["']/i,
    type: "OAuth2 Client ID",
    severity: "LOW",
  },

  // Optimized Regexes

  // ===== Cloud Keys =====
  {
    regex: /\bAIza[A-Za-z0-9_\-]{35}\b/i,
    type: "Google API Key",
    severity: "HIGH",
  },
  {
    regex:
      /\b(?:aws|amazon)?(?:secret|access(?:_?key|_?token))[:=][A-Za-z0-9\/+=]{20,50}\b/i,
    type: "AWS Secret Key",
    severity: "HIGH",
  },

  // ===== Long Generic Tokens =====
  {
    regex: /\b[A-Za-z0-9\/+]{56}\b/i,
    type: "Generic 56-char Token",
    severity: "HIGH",
  },
  {
    regex: /\b[A-Za-z0-9\/+]{86}==\b/i,
    type: "Generic 86-char Token",
    severity: "HIGH",
  },

  // ===== Private Keys / Certificates =====
  {
    regex:
      /^-----BEGIN (?:RSA|EC|DSA)? PRIVATE KEY-----[\s\S]{0,2000}-----END (?:RSA|EC|DSA)? PRIVATE KEY-----$/m,
    type: "Private Key",
    severity: "HIGH",
  },
  {
    regex:
      /^-----BEGIN CERTIFICATE-----[\s\S]{0,2000}-----END CERTIFICATE-----$/m,
    type: "Base64 Certificate/Key",
    severity: "MEDIUM",
  },
  // ===== Azure / AWS / GCP =====
  {
    regex:
      /Endpoint=sb:\/\/[^;]+servicebus\.windows\.net;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+\/]{43}=/i,
    type: "Azure Service Bus SAS",
    severity: "HIGH",
  },
  {
    regex:
      /https?:\/\/[^?\s]+\.(?:blob|queue|file|table)\.core\.windows\.net\/[^\s?]*\?[^#\s]*\bsv=[^&]+&[^#\s]*\bsig=[A-Za-z0-9%]{20,}%3d/i,
    type: "Azure Storage SAS URL",
    severity: "MEDIUM",
  },
  {
    regex: /x-goog-signature=[A-Fa-f0-9]{64,}/i,
    type: "GCP Signed URL",
    severity: "HIGH",
  },
  {
    regex: /redis\.cache\.windows\.net;.*?\bPassword=([^;]{8,})/i,
    type: "Azure Redis Password",
    severity: "HIGH",
  },
];

// False positives list
var FALSE_POSITIVES = [
  "clientid",
  "clientsecret",
  "string",
  "n/a",
  "null",
  "na",
  "true",
  "false",
  "value_here",
  "your_key",
  "your_api_key_here",
  "demo_token",
  "test1234",
  "dummysecret",
  "{token}",
  "bearer{token}",
  "placeholder",
  "insert_value",
  "AKIAFAKEKEY",
  "ghp_testtoken",
  "demo_secret",
  "sample_token",
  "test_token_123",
  "gho_dummyvalue",
  "ghp_exampletoken",
  "gho_placeholdertoken",
  "pk_test_1234567890abcdef",
  "sk_test_abcdef1234567890",
  "AIzaSyDUMMYKEY1234567890",
  "your_api_key",
  "your_secret_key",
  "insert_token_here",
  "testapikey",
  "sampleapikey",
  "dummyapikey",
  "fake_jwt_token",
  "jwt_token_example",
  "Bearer demo_token",
  "Bearer test_token",
  "access_token=demo123",
  'clientSecret: "changeme"',
  'clientSecret: "demo_secret"',
  'clientSecret: "your_secret"',
  "authorization: testauthvalue",
  "auth_token=sample123",
  "authkey=demo_key",
  "authtoken=placeholder",
  "sessionid=testsession",
  'OAuth2ClientId: "demo-client"',
  'clientId: "00000000-0000-0000-0000-000000000000"',
  'clientId: "demo-client-id"',
  "redis.cache.windows.net;Password=dummypass",
  "SharedAccessKey=demoaccesskey",
  "x-goog-signature=0000000000000000000000000000000000000000000000000000000000000000",
  "ghp_1234567890abcdef1234567890abcdef1234",
  "github_pat_demo",
  "npm_demo_token",
  "hf_demo_token",
];

function isFalsePositiveKV(kvString) {
  if (!kvString || kvString.length < 1) return true;
  var kvMatch = kvString.match(
    /["']?([^"']+)["']?\s*[:=]\s*["']?([^"']+)["']?/
  );
  if (!kvMatch || kvMatch.length < 3) return false;
  var key = kvMatch[1].toLowerCase().trim();
  var value = kvMatch[2].toLowerCase().trim();
  value = value.replace(/[\s"'{}]/g, "");
  if (value.length < 6) return true;
  var contextKeys = ["example", "description", "title", "note"];
  for (var i = 0; i < contextKeys.length; i++) {
    if (key.indexOf(contextKeys[i]) !== -1) return true;
  }
  var junkTokens = [
    "test",
    "sample",
    "dummy",
    "mock",
    "try",
    "placeholder",
    "your",
    "insert",
  ];
  for (var i = 0; i < junkTokens.length; i++) {
    if (
      value.indexOf(junkTokens[i]) !== -1 ||
      key.indexOf(junkTokens[i]) !== -1
    )
      return true;
  }
  for (var i = 0; i < FALSE_POSITIVES.length; i++) {
    if (value === FALSE_POSITIVES[i]) return true;
  }
  return false;
}

// Redact sensitive values
function redactSecret(secret) {
  var kvMatch = secret.match(/["']?([^"']+)["']?\s*[:=]\s*["']?([^"']+)["']?/);
  if (kvMatch && kvMatch.length >= 3) {
    var key = kvMatch[1];
    var value = kvMatch[2];
    return key + ': "' + value.substring(0, 5) + '..."';
  }

  if (secret.length > 20) {
    return secret.substring(0, 10) + "...";
  }

  return secret;
}

// Passive scan
function scan(ps, msg, src) {
  print(
    "DEBUG: Scan running on URL: " + msg.getRequestHeader().getURI().toString()
  );

  var startTime = Date.now();
  var MAX_EXECUTION_MS = 5000; // 5 seconds
  function isTimedOut() {
    return Date.now() - startTime > MAX_EXECUTION_MS;
  }

  function processMatch(match, entry, findings, SEVERITY_ORDER, source) {
    var token = match.length > 1 ? match[1] : match[0];
    print(
      "DEBUG: Matched regex [" + entry.type + "] in " + source + " -> " + token
    );

    if (!isFalsePositiveKV(token)) {
      var key = token + "_" + source; // include source to distinguish same token in different locations
      if (findings[key]) {
        if (
          SEVERITY_ORDER[entry.severity] >
          SEVERITY_ORDER[findings[key].severity]
        ) {
          findings[key] = {
            evidence: token,
            type: entry.type,
            severity: entry.severity,
            source: source,
          };
        }
      } else {
        findings[key] = {
          evidence: token,
          type: entry.type,
          severity: entry.severity,
          source: source,
        };
      }
    }
  }

  function scanContent(content, source, findings, SEVERITY_ORDER) {
    if (!content || content.length < 6) return;
    if (content.length > 200000) return; // skip >200 KB

    for (var j = 0; j < SECRET_REGEXES.length; j++) {
      var entry = SECRET_REGEXES[j];
      var regex = entry.regex;
      regex.lastIndex = 0;

      var match;
      var matchCount = 0;
      var MAX_MATCHES_PER_REGEX = 100;

      if (regex.global) {
        while ((match = regex.exec(content)) !== null) {
          if (++matchCount > MAX_MATCHES_PER_REGEX || isTimedOut()) {
            print(
              "DEBUG: Aborted regex [" +
                entry.type +
                "] in " +
                source +
                " due to timeout or match limit."
            );
            break;
          }
          processMatch(match, entry, findings, SEVERITY_ORDER, source);
        }
      } else {
        match = regex.exec(content);
        if (match && !isTimedOut()) {
          processMatch(match, entry, findings, SEVERITY_ORDER, source);
        }
      }

      if (isTimedOut()) {
        print("DEBUG: Scan aborted due to timeout.");
        break;
      }
    }
  }

  const SEVERITY_ORDER = { LOW: 1, MEDIUM: 2, HIGH: 3 };
  var findings = {}; // token_source -> best finding

  // scan HTTP Response Body
  var rawBody = msg.getResponseBody();
  if (rawBody) {
    var body = "" + rawBody.toString();
    if (body.length >= 20) {
      scanContent(body, "response_body", findings, SEVERITY_ORDER);
    }
  }

  // scan Request URL Path
  var uri = msg.getRequestHeader().getURI();
  if (uri) {
    var urlPath = uri.getPath();
    if (urlPath && urlPath.length > 1) {
      // URL decode the path to catch encoded credentials
      try {
        var decodedPath = java.net.URLDecoder.decode(urlPath, "UTF-8");
        scanContent(decodedPath, "url_path", findings, SEVERITY_ORDER);
      } catch (e) {
        // Fallback to original path if decoding fails
        scanContent(urlPath, "url_path", findings, SEVERITY_ORDER);
      }
    }
  }

  // scan URL Parameters
  if (uri) {
    var query = uri.getQuery();
    if (query && query.length > 0) {
      // URL decode the query string to catch encoded credentials
      try {
        var decodedQuery = java.net.URLDecoder.decode(query, "UTF-8");
        scanContent(decodedQuery, "url_parameters", findings, SEVERITY_ORDER);
      } catch (e) {
        // Fallback to original query if decoding fails
        scanContent(query, "url_parameters", findings, SEVERITY_ORDER);
      }
    }
  }

  var tokens = Object.keys(findings);
  if (tokens.length === 0) return;

  for (var i = 0; i < tokens.length; i++) {
    var f = findings[tokens[i]];
    var alertName, alertDescription, alertSolution;

    switch (f.source) {
      case "response_body":
        alertName = "Exposed " + f.type + " in HTTP Response";
        alertDescription =
          "A potential " + f.type + " was found in the HTTP response body.";
        alertSolution =
          "Remove hardcoded secrets from responses and ensure sensitive endpoints require authentication.";
        break;
      case "url_path":
        alertName = "Exposed " + f.type + " in URL Path";
        alertDescription =
          "A potential " +
          f.type +
          " was found in the request URL path. This could indicate credentials being passed in the URL, which is visible in server logs, browser history, and referrer headers.";
        alertSolution =
          "Never include credentials in URL paths. Use secure authentication mechanisms such as Authorization headers, secure cookies, or POST body parameters over HTTPS.";
        break;
      case "url_parameters":
        alertName = "Exposed " + f.type + " in URL Parameters";
        alertDescription =
          "A potential " +
          f.type +
          " was found in URL query parameters. This could indicate credentials being passed as URL parameters, which is visible in server logs, browser history, and referrer headers.";
        alertSolution =
          "Never include credentials in URL parameters. Use secure authentication mechanisms such as Authorization headers, secure cookies, or POST body parameters over HTTPS.";
        break;
      default:
        alertName = "Exposed " + f.type;
        alertDescription = "A potential " + f.type + " was found.";
        alertSolution =
          "Remove hardcoded secrets and use secure authentication mechanisms.";
    }

    ps.newAlert()
      .setRisk(f.severity === "HIGH" ? 3 : f.severity === "MEDIUM" ? 2 : 1)
      .setConfidence(2)
      .setName(alertName)
      .setDescription(alertDescription)
      .setSolution(alertSolution)
      .setEvidence(redactSecret(f.evidence))
      .setOtherInfo(
        "Matched type: " +
          f.type +
          " (Severity: " +
          f.severity +
          ") - Found in: " +
          f.source
      )
      .setCweId(522)
      .setWascId(13)
      .setMessage(msg)
      .raise();
  }

  ps.addHistoryTag("credential_exposure");
}

// Limit scanning to default history types
function appliesToHistoryType(historyType) {
  return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
}
