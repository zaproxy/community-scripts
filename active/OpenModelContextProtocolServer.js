// Description: This script detects potentially exposed MCP servers by sending MCP initialization requests
// Author: Daniel Santos (@bananabr)

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);
var CommonAlertTag = Java.type("org.zaproxy.addon.commonlib.CommonAlertTag");

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100045
name: Open MCP Server Detection
description: >
  This script detects potentially exposed Model Context Protocol (MCP) servers
  by sending MCP initialization requests and analyzing responses for characteristic
  MCP protocol signatures.
solution: >
  Ensure MCP servers are properly secured and not exposed to unauthorized access.
  Implement proper authentication and access controls for MCP endpoints.
references:
  - https://spec.modelcontextprotocol.io/specification/
  - https://github.com/modelcontextprotocol/specification
category: server
risk: medium
confidence: medium
cweId: 306  # CWE-306: Missing Authentication for Critical Function
wascId: 13  # WASC-13: Information Leakage
alertTags:
  ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue()}
  ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()}: ${CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue()}
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/active/OpenModelContextProtocolServer.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

/**
 * Scans a host for exposed MCP servers
 * @param as - ActiveScan object
 * @param msg - HttpMessage object
 */
function scanHost(as, msg) {
  print(
    "MCP Server Detector: Scanning " +
      msg.getRequestHeader().getURI().toString()
  );

  // Check if the scan was stopped
  if (as.isStop()) {
    return;
  }

  // Get the original URI
  var uri = msg.getRequestHeader().getURI();
  var baseUrl = uri.getScheme() + "://" + uri.getHost();
  if (uri.getPort() !== -1) {
    baseUrl += ":" + uri.getPort();
  }

  // Common MCP server endpoints to test
  var mcpEndpoints = [
    "/", // Root path - Default for many MCP servers, @modelcontextprotocol/server-stdio
    "/mcp", // Standard MCP path - Custom implementations, MCP reference servers
    "/mcp/", // MCP with trailing slash - Web-based MCP servers, Express.js implementations
    "/api/mcp", // API-style path - REST API wrappers, enterprise MCP gateways
    "/rpc", // Generic RPC endpoint - JSON-RPC servers that support MCP, multi-protocol servers
    "/jsonrpc", // JSON-RPC endpoint - Pure JSON-RPC implementations with MCP support
    "/mcp-server", // Explicit server path - Standalone MCP server deployments, Docker containers
    "/v1/mcp", // Versioned API path - Versioned MCP APIs, enterprise/production deployments
  ];

  // Add current path if it's not null or empty
  var currentPath = uri.getPath();
  if (currentPath && currentPath !== "/" && currentPath !== "") {
    mcpEndpoints.push(currentPath);
  }

  // MCP initialization payload
  var mcpInitPayload = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {
        roots: {
          listChanged: true,
        },
        sampling: {},
        elicitation: {},
      },
      clientInfo: {
        name: "ZAPActiveScript",
        title: "ZAP Open MCP Active Script",
        version: "1.0.0",
      },
    },
  });

  // Test each potential MCP endpoint
  for (var i = 0; i < mcpEndpoints.length; i++) {
    if (as.isStop()) {
      return;
    }

    var endpoint = mcpEndpoints[i];
    var foundMcp = testMcpEndpoint(as, msg, baseUrl + endpoint, mcpInitPayload);

    // Break out of loop if we found a vulnerable MCP server
    if (foundMcp) {
      print(
        "MCP Server Detector: Found vulnerable MCP server, stopping endpoint enumeration"
      );
      break;
    }
  }
}

/**
 * Tests a specific endpoint for MCP server responses
 * @param as - ActiveScan object
 * @param originalMsg - Original HttpMessage
 * @param testUrl - URL to test
 * @param payload - MCP payload to send
 * @return boolean - true if MCP server found, false otherwise
 */
function testMcpEndpoint(as, originalMsg, testUrl, payload) {
  try {
    print("MCP Server Detector: Testing endpoint " + testUrl);
    var testMsg = originalMsg.cloneRequest();
    var requestHeader = testMsg.getRequestHeader();

    // Set the new URL using Apache Commons HttpClient URI
    var HttpClientURI = Java.type("org.apache.commons.httpclient.URI");
    requestHeader.setURI(new HttpClientURI(testUrl, false));
    requestHeader.setMethod("POST");

    // Set appropriate headers
    requestHeader.setHeader("Accept", "application/json, text/event-stream");
    requestHeader.setHeader("Content-Type", "application/json");

    // Set the request body
    testMsg.setRequestBody(payload);

    // Send the request
    as.sendAndReceive(testMsg, false, false);

    // Analyze the response and return whether MCP server was found
    return analyzeMcpResponse(as, testMsg, payload);
  } catch (e) {
    print("MCP Server Detector: Error testing endpoint " + testUrl + ": " + e);
    return false;
  }
}

/**
 * Analyzes the response for MCP server indicators
 * @param as - ActiveScan object
 * @param msg - HttpMessage with response
 * @param originalPayload - Original payload sent
 * @return boolean - true if MCP server detected, false otherwise
 */
function analyzeMcpResponse(as, msg, originalPayload) {
  var response = msg.getResponseBody().toString();
  var responseHeader = msg.getResponseHeader();
  var statusCode = responseHeader.getStatusCode();

  print(
    "MCP Server Detector: Analyzing response from " +
      msg.getRequestHeader().getURI().toString()
  );
  print("MCP Server Detector: Status Code: " + statusCode);
  print(
    "MCP Server Detector: Response length: " + msg.getResponseBody().length()
  );

  // Get response headers for additional analysis
  var contentType = responseHeader.getHeader("Content-Type");
  var mcpSessionId = responseHeader.getHeader("Mcp-Session-Id");
  var transferEncoding = responseHeader.getHeader("Transfer-Encoding");
  var server = responseHeader.getHeader("Server");

  print("MCP Server Detector: Content-Type: " + contentType);
  print("MCP Server Detector: Mcp-Session-Id: " + mcpSessionId);
  print("MCP Server Detector: Transfer-Encoding: " + transferEncoding);

  // Analyze content types for MCP compliance
  var hasMcpHeaders = mcpSessionId !== null;
  var hasEventStream =
    contentType !== null && contentType.indexOf("text/event-stream") !== -1;
  var hasJsonResponse =
    contentType !== null &&
    contentType.toLowerCase().indexOf("application/json") !== -1;

  // MCP servers MUST respond with either text/event-stream OR application/json for JSON-RPC requests
  var hasMcpCompliantContentType = hasEventStream || hasJsonResponse;

  // Skip analysis if no valid response and no MCP indicators
  if (
    !hasMcpHeaders &&
    !hasMcpCompliantContentType &&
    (response.length === 0 || statusCode !== 200)
  ) {
    return false;
  }

  // For 200 responses with MCP-compliant content types, proceed with analysis even if body is empty
  // (SSE streams might not have loaded the body yet)
  var shouldAnalyze =
    (statusCode === 200 && hasMcpCompliantContentType) ||
    hasMcpHeaders ||
    response.length > 0;
  if (!shouldAnalyze) {
    return false;
  }

  // Debug: Log the first 200 characters of response for debugging
  var debugResponse =
    response.length > 200 ? response.substring(0, 200) + "..." : response;
  print("MCP Server Detector: Response preview: " + debugResponse);

  var isValidMcp = false;
  var evidence = "";
  var confidence = 1; // Low confidence by default
  var risk = 1; // Low risk by default

  // Strict MCP server validation according to specification requirements

  // Case 1: SSE format - Content-Type is text/event-stream AND status 200 AND has Mcp-Session-Id header
  if (hasEventStream && statusCode === 200 && hasMcpHeaders) {
    isValidMcp = true;
    confidence = 4; // Confirmed MCP SSE server
    risk = 3; // High risk - exposed MCP server
    evidence =
      "Confirmed MCP Server (SSE format): text/event-stream content type with Mcp-Session-Id header";
  }
  // Case 2: SSE format - Content-Type is text/event-stream AND status 200 (without MCP session header)
  else if (hasEventStream && statusCode === 200 && !hasMcpHeaders) {
    isValidMcp = true;
    confidence = 2; // Lower confidence without MCP session header
    risk = 2; // Medium risk - might be MCP server
    evidence =
      "Suspected MCP Server (SSE format): text/event-stream content type without Mcp-Session-Id header";
  }
  // Case 3: JSON format - Content-Type is application/json AND status 200 AND valid MCP initialize response structure
  else if (hasJsonResponse && statusCode === 200) {
    // Parse JSON response to validate MCP structure
    var isValidMcpJson = false;
    var jsonParseError = null;

    try {
      if (response.length > 0) {
        var jsonResponse = JSON.parse(response);

        // Check for valid MCP initialize response structure
        if (
          jsonResponse &&
          jsonResponse.jsonrpc === "2.0" &&
          jsonResponse.id !== undefined &&
          jsonResponse.result &&
          jsonResponse.result.protocolVersion &&
          jsonResponse.result.capabilities &&
          jsonResponse.result.serverInfo
        ) {
          isValidMcpJson = true;
        }
      }
    } catch (e) {
      jsonParseError = e.toString();
    }

    if (isValidMcpJson) {
      isValidMcp = true;
      confidence = 4; // Confirmed MCP JSON server
      risk = 3; // High risk - exposed MCP server
      evidence =
        "Confirmed MCP Server (JSON format): Valid MCP initialize response with required structure " +
        "(jsonrpc: '2.0', id, result.protocolVersion, result.capabilities, result.serverInfo)";
    } else if (jsonParseError) {
      print("MCP Server Detector: JSON parse error: " + jsonParseError);
    }
  }

  // Only raise alert if we detected a valid MCP server
  if (isValidMcp) {
    // Add strict MCP specification validation details
    evidence += "\n\nMCP Specification Validation:";
    if (hasEventStream && hasMcpHeaders && statusCode === 200) {
      evidence +=
        "\n✓ SSE Format: text/event-stream + Mcp-Session-Id header + HTTP 200";
    }
    if (hasJsonResponse && statusCode === 200) {
      evidence +=
        "\n✓ JSON Format: application/json + HTTP 200 + Valid MCP response structure";
    }

    // Add header information to evidence
    evidence += "\n\nHTTP Response Details:";
    evidence += "\nStatus Code: " + statusCode;
    if (contentType) evidence += "\nContent-Type: " + contentType;
    if (mcpSessionId) evidence += "\nMcp-Session-Id: " + mcpSessionId;
    if (transferEncoding)
      evidence += "\nTransfer-Encoding: " + transferEncoding;
    if (server) evidence += "\nServer: " + server;

    // Include response snippet in evidence (first 500 chars)
    if (response.length > 0) {
      var responseSnippet =
        response.length > 500 ? response.substring(0, 500) + "..." : response;
      evidence += "\n\nResponse Body:\n" + responseSnippet;
    } else if (hasEventStream && hasMcpHeaders) {
      evidence +=
        "\n\nNote: SSE stream established - response body may be empty initially";
    } else {
      evidence += "\n\nNote: Response body was empty";
    }

    raiseMcpAlert(as, msg, evidence, confidence, risk, originalPayload);
    return true; // MCP server found
  }

  return false; // No MCP server detected
}

/**
 * Raises an alert for detected MCP server
 * @param as - ActiveScan object
 * @param msg - HttpMessage
 * @param evidence - Evidence string
 * @param confidence - Confidence level (0-4)
 * @param risk - Risk level (0-3)
 * @param payload - Original payload sent
 */
function raiseMcpAlert(as, msg, evidence, confidence, risk, payload) {
  print(
    "MCP Server Detector: Raising alert for " +
      msg.getRequestHeader().getURI().toString()
  );

  var alertTitle = "Open MCP Server Detected";
  var description =
    "A confirmed Model Context Protocol (MCP) server was detected through strict specification validation. " +
    "The server properly responds to MCP initialize requests with either: (1) Server-Sent Events format " +
    "(text/event-stream + Mcp-Session-Id header), or (2) Valid JSON format (application/json + proper MCP response structure). " +
    "MCP servers provide AI assistants with controlled access to tools and data sources. " +
    "If this server is unintentionally exposed, it could allow unauthorized access to internal tools, resources, or sensitive information.";

  var solution =
    "1. Verify if this MCP server should be publicly accessible\n" +
    "2. Implement proper authentication and authorization\n" +
    "3. Use network-level restrictions (firewall, VPN)\n" +
    "4. Regularly audit MCP server configurations\n" +
    "5. Monitor MCP server access logs";

  var reference =
    "Model Context Protocol Specification: https://spec.modelcontextprotocol.io/specification/";

  var otherInfo =
    "MCP servers support two response formats:\n" +
    "1. Server-Sent Events (text/event-stream) - for streaming responses\n" +
    "2. JSON (application/json) - for single JSON object responses\n\n" +
    "MCP servers typically expose methods like:\n" +
    "- initialize: Server initialization\n" +
    "- tools/list: Available tools\n" +
    "- resources/list: Available resources\n" +
    "- prompts/list: Available prompts\n\n" +
    "Original request payload:\n" +
    payload;

  as.newAlert()
    .setRisk(risk)
    .setConfidence(confidence)
    .setName(alertTitle)
    .setDescription(description)
    .setAttack(payload)
    .setEvidence(evidence)
    .setOtherInfo(otherInfo)
    .setSolution(solution)
    .setReference(reference)
    .setMessage(msg)
    .raise();
}

/**
 * Parameter-based scanning (not typically used for this type of detection)
 * @param as - ActiveScan object
 * @param msg - HttpMessage
 * @param param - Parameter name
 * @param value - Parameter value
 */
function scan(as, msg, param, value) {
  // For MCP server detection, we focus on endpoint discovery rather than parameter manipulation
  // This function is included for completeness but not actively used
  return;
}
