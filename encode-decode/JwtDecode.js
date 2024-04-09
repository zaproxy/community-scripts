// JWT Decode by 0mgfriday
var Base64 = Java.type("java.util.Base64");
var String = Java.type("java.lang.String");
var StandardCharsets = Java.type("java.nio.charset.StandardCharsets");

/**
 * Decode JWT into a text representation
 *
 * @param {EncodeDecodeScriptHelper} helper - A helper object with various utility methods.
 *     For more details see https://github.com/zaproxy/zap-extensions/tree/main/addOns/encoder/src/main/java/org/zaproxy/addon/encoder/processors/script/EncodeDecodeScriptHelper.java
 * @param {String} value - JWT to decode
 * @returns {EncodeDecodeResult} - Decoded JWT (JSON)
 */
function process(helper, value) {
  var parts = value.split(".");

  if (parts.length == 2 || parts.length == 3) {
    try {
      var result =
        formatJson(b64decode(parts[0])) +
        "\n" +
        formatJson(b64decode(parts[1]));

      if (parts.length == 3 && parts[2] != "") {
        result += "\n{SIGNATURE}";
      }

      return helper.newResult(result);
    } catch (err) {
      return helper.newError("Invalid JWT: Unable to decode");
    }
  }

  return helper.newError("Invalid JWT");
}

function b64decode(s) {
  var bytes = Base64.getUrlDecoder().decode(s);
  return new String(bytes, StandardCharsets.UTF_8);
}

function formatJson(json) {
  return JSON.stringify(JSON.parse(json), null, 2);
}
