 /**
 * Converts a string payload to hex.
 * 
 * Created to add functionality found in Burp to solve Natas19
 * https://www.youtube.com/watch?v=z3RtpWZ_R3Q
 *
 * EN10
 */

function process(payload) {
  var hex = '';
  var i;
  for (i = 0; i < payload.length; i++) {
    hex += payload.charCodeAt(i).toString(16);
  }
  return hex;
}
