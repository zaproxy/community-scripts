/**
 * Input Vector script to help Zap attack compound cookies, i.e. cookies that contain multiple parameters
 * Format of a Compound cookie is Classic ASP compliant, i.e. of the form:
 *        <compoundcookie>=<p1name>=<p1value>&<p2name>=<p2value>&...
 * where parameter names and values must be URI component encoded. Generates parameters in the form:
 *        <compoundcookie>:<p1name>=<p1value>
 *        <compoundcookie>:<p2name>=<p2value>
 *        ...
 * These compound cookies should be filtered out in Active Scan Exclude Param to stop ZAP attacking these cookies directly.
 */
var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var HtmlParameter = Java.type("org.parosproxy.paros.network.HtmlParameter");
var COOKIE_TYPE = org.parosproxy.paros.network.HtmlParameter.Type.cookie;

/* List of compound cookies to target - either burn in list below (i.e. ccList = [ "<compoundcookie1>", "<compoundcookie2>", ... ]; )
 * or set via 'CompoundCookies' global var as a '&' separated list (i.e. "<compoundcookie1>&<compoundcookie2>&..." ) */
var ccList = [];

function parseParameters(helper, msg) {
  var headers = msg.getRequestHeader();
  var cookies = headers.getCookieParams();
  var cookieIndex;
  var equalsIndex;
  var loopCounter;
  var cookieList;
  if (ccList.length == 0) {
    var ei;
    if (
      (ei = ScriptVars.getGlobalVar("CompoundCookies")).equals("") ||
      (ccList = ei.split("&")).length == 0
    ) {
      print(
        "CompoundCookie Setup Error: GlobalVar CompoundCookies must be set to '&' separated list of compound cookies"
      );
      return;
    }
    //print('CompoundCookie list: ' + ccList);
  }
  //print('parseParameters: ' + msg.getRequestHeader().getURI().toString());
  for (var ci = cookies.iterator(); ci.hasNext(); ) {
    var cc = ci.next();

    if ((cookieIndex = ccList.indexOf(cc.getName())) >= 0) {
      cookieList = cc.getValue().split("&");
      //print("  Splitting: " + ccList[cookieIndex]);
      for (loopCounter = 0; loopCounter < cookieList.length; loopCounter++) {
        if ((equalsIndex = cookieList[loopCounter].indexOf("=")) > 0) {
          //print("    Var " + decodeURIComponent(cookieList[loopCounter].substring(0,equalsIndex)) + "=" + decodeURIComponent(cookieList[loopCounter].substring(equalsIndex+1)));
          helper.addParamQuery(
            ccList[cookieIndex] +
              ":" +
              decodeURIComponent(
                cookieList[loopCounter].substring(0, equalsIndex)
              ),
            decodeURIComponent(
              cookieList[loopCounter].substring(equalsIndex + 1)
            )
          );
        }
      }
    }
  }
}

/* Only one parameter is changed at a time so only one compound cookie to update */
function setParameter(helper, msg, param, value, escaped) {
  var size = helper.getParamNumber();
  var pos = helper.getCurrentParam().getPosition();
  var loopCounter;
  var colonIndex;
  var paramName;
  var cookieName;
  var prefix;
  var val;
  if (
    pos < size &&
    (colonIndex = (paramName = helper.getParamName(pos)).indexOf(":")) > 0 &&
    ccList.indexOf((cookieName = paramName.substring(0, colonIndex))) >= 0
  ) {
    var headers = msg.getRequestHeader();
    var cookies = headers.getCookieParams();
    prefix = cookieName + ":";
    val = "";
    for (loopCounter = 0; loopCounter < size; loopCounter++) {
      if (loopCounter == pos) {
        val =
          encodeURIComponent(
            helper.getParamName(loopCounter).slice(colonIndex + 1)
          ) +
          "=" +
          encodeURIComponent(value) +
          "&" +
          val;
      } else if (
        (paramName = helper.getParamName(loopCounter)).startsWith(prefix)
      ) {
        val =
          encodeURIComponent(paramName.slice(colonIndex + 1)) +
          "=" +
          encodeURIComponent(helper.getParamValue(loopCounter)) +
          "&" +
          val;
      }
    }
    /* remove trailing '&' */
    val = val.slice(0, -1);
    //print('SetParameter: ' + cookieName + '=' + val);
    val = new HtmlParameter(COOKIE_TYPE, cookieName, val);
    for (var ci = cookies.iterator(); ci.hasNext(); ) {
      var cc = ci.next();
      if (cc.getName().equals(cookieName)) {
        ci.remove();
        break;
      }
    }
    cookies.add(val);
    msg.getRequestHeader().setCookieParams(cookies);
  } else {
    print(
      "CompoundCookie SetParameter Error: Invalid input " +
        size +
        ", " +
        pos +
        " -> " +
        paramName
    );
  }
}

/* Return null to Use default method */
function getLeafName(helper, nodeName, msg) {
  return null;
}

/* Return null to Use default method */
function getTreePath(helper, msg) {
  return null;
}
