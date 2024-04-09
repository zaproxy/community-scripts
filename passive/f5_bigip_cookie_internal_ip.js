// Note that new passive scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"

// Persistence cookies returned by F5 BigIP devices are used for load balancing
// and if not properly configured, may reveal IP addresses and ports of internal (RFC1918) components.
// This script passively scans for such cookies being set and attempts to decode them.
// If an analyzed cookie decodes to a RFC1918 IPv4 address then an alert is raised.

// Ref: https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html
// Author: kingthorin
// 20150828 - Initial submission
// 20160117 - Updated to include ipv6 variants - jkbowser[at]gmail[dot]com

var Locale = Java.type("java.util.Locale");

function scan(ps, msg, src) {
  //Setup some details we will need for alerts later if we find something
  var alertRisk = [1, 0];
  var alertConfidence = 3;
  var alertTitle = [
    "Internal IP Exposed via F5 BigIP Persistence Cookie",
    "IP Exposed via F5 BigIP Presistence Cookie",
  ];
  var alertDesc = [
    "The F5 Big-IP Persistence cookie set for this website can be decoded to a specific internal IP and port. An attacker may leverage this information to conduct Social Engineering attacks or other exploits.",
    "The F5 Big-IP Persistence cookie set for this website can be decoded to a specific IP and port. An attacker may leverage this information to conduct Social Engineering attacks or other exploits.",
  ];
  var alertSolution = "Configure BIG-IP cookie encryption.";
  var alertRefs =
    "https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html";
  var cweId = 311;
  var wascId = 13;

  var url = msg.getRequestHeader().getURI().toString();
  //Only check when a cookie is set
  if (msg.getResponseHeader().getHeaders("Set-Cookie")) {
    var cookiesList = msg.getResponseHeader().getHttpCookies(); //Set-Cookie in Response
    cookiesList.addAll(msg.getRequestHeader().getHttpCookies()); //Cookie in Request
    var cookiesArr = cookiesList.toArray();

    for (var idx in cookiesArr) {
      var cookieName = cookiesArr[idx].getName();
      var cookieValue = cookiesArr[idx].getValue();
      if (
        cookieName.toLowerCase(Locale.ROOT).contains("bigip") &&
        !cookieValue.toLowerCase(Locale.ROOT).contains("deleted")
      ) {
        var cookieChunks = cookieValue.split("."); //i.e.: 3860990474.36895.0000
        //Decode IP
        try {
          var theIP = decodeIP(cookieChunks[0]);
        } catch (e) {
          continue; //Something went wrong
        }
        //Decode Port
        var thePort = decodePort(cookieChunks[1]);

        if (isLocal(theIP)) {
          //RFC1918 and RFC4193

          if (theIP.match(/:/g)) {
            //matching again just so I can format it correctly with []
            var decodedValue = "[" + theIP + "]:" + thePort;
          } else {
            decodedValue = theIP + ":" + thePort;
          }
          var alertOtherInfo = cookieValue + " decoded to " + decodedValue;
          //ps.raiseAlert(risk, confidence, title, description, url, param, attack, otherinfo, solution, evidence, cweId, wascId, msg);
          ps.raiseAlert(
            alertRisk[0],
            alertConfidence,
            alertTitle[0],
            alertDesc[0],
            url,
            cookieName,
            "",
            alertOtherInfo,
            alertSolution + "\n" + alertRefs,
            cookieValue,
            cweId,
            wascId,
            msg
          );
        } else if (isExternal(theIP)) {
          if (theIP.match(/:/g)) {
            //matching again just so I can format it correctly with []
            decodedValue = "[" + theIP + "]:" + thePort;
          } else {
            decodedValue = theIP + ":" + thePort;
          }
          alertOtherInfo = cookieValue + " decoded to " + decodedValue;
          //ps.raiseAlert(risk, confidence, title, description, url, param, attack, otherinfo, solution, evidence, cweId, wascId, msg);
          ps.raiseAlert(
            alertRisk[1],
            alertConfidence,
            alertTitle[1],
            alertDesc[1],
            url,
            cookieName,
            "",
            alertOtherInfo,
            alertSolution + "\n" + alertRefs,
            cookieValue,
            cweId,
            wascId,
            msg
          );
        } else {
          //Not what we're looking for
          continue;
        }
      }
    }
  }
}

function decodeIP(ipChunk) {
  //this is our check for IPv6 cookie.  BigIP F5 documentation says all are prefixed with "vi"
  if (ipChunk.substring(0, 2) == "vi") {
    //get rid of the prefixed vi
    ipChunk = ipChunk.substring(2);

    //create array in groups of 4.
    //makes vi20010112000000900000000000000030 into 2001,0112,0000,0090,0000,0000,0000,0030
    var encodedIP = ipChunk.match(/[0-9a-f]{4}/gi);

    //first, cast array to string
    //then replace , with :
    var ipv6 = encodedIP.toString().replace(/,/g, ":");
    return ipv6;
  } else {
    //not ipv6, so process it as ipv4

    var backwardIpHex = java.net.InetAddress.getByName(ipChunk);
    var backwardAddress = backwardIpHex.getHostAddress();
    var ipPieces = backwardAddress.split(".");
    var theIP =
      ipPieces[3] + "." + ipPieces[2] + "." + ipPieces[1] + "." + ipPieces[0];
    return theIP;
  }
}

function isLocal(ip) {
  if (ip.match(/:/g)) {
    //match on ipv6 notation
    try {
      //isSiteLocalAddress only returns true for FEC0, using RFC4193 definition of fc00, matching on beginning string regexp
      if (java.net.InetAddress.getByName(ip) && ip.match(/(^fc00)/im)) {
        return true; //it is local per RFC4193
      }
    } catch (e) {
      return false; //not confirmed local ipv6
    }
  } else {
    try {
      if (java.net.InetAddress.getByName(ip).isSiteLocalAddress()) {
        return true; //RFC1918 and IPv4
      }
    } catch (e) {
      return false; //Not confirmed local IPv4
    }
  }
}

function isExternal(ip) {
  try {
    if (java.net.InetAddress.getByName(ip)) {
      //just testing for valid format to verify it's not encrypted
      return true; //it is a valid IP, likely external
    }
  } catch (e) {
    return false; //Not valid IP, so it's likely an encrypted cookie
  }
}

function decodePort(portChunk) {
  //port processing is same for ipv4 and ipv6
  var backwardPortHex = java.lang.Integer.toHexString(
    java.lang.Integer.parseInt(portChunk)
  );
  var assembledPortHex =
    backwardPortHex.substring(2, 4) + backwardPortHex.substring(0, 2);
  var thePort = java.lang.Integer.parseInt(assembledPortHex, 16);
  return thePort;
}

// TODO List
//Handle IPv4 pool members in non-default route domains
//Handle IPv6 pool members in non-default route domains
