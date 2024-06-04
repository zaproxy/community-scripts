// CreditCard Finder by freakyclown@gmail.com

var ScanRuleMetadata = Java.type(
  "org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata"
);

function getMetadata() {
  return ScanRuleMetadata.fromYaml(`
id: 100008
name: Information Disclosure - Credit Card Number
description: A credit card number was found in the HTTP response body.
solution: >
  Encrypt credit card numbers during transmission, use tokenization,
  and adhere to PCI DSS standards for secure handling and storage.
risk: high
confidence: medium
cweId: 311  # CWE-311: Missing Encryption of Sensitive Data
wascId: 13  # WASC-13: Information Leakage
status: alpha
codeLink: https://github.com/zaproxy/community-scripts/blob/main/passive/Find%20Credit%20Cards.js
helpLink: https://www.zaproxy.org/docs/desktop/addons/community-scripts/
`);
}

function scan(helper, msg, src) {
  var body = msg.getResponseBody().toString();

  // lets make some regular expressions for well known credit cards
  // regex must appear within /( and )/g
  var re_visa = /([3-5][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})/g; //visa or mastercard
  var re_amex = /(3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5})/g; //amex
  var re_disc = /(6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})/g; //discovery
  var re_diner = /(3(?:0[0-5]|[68][0-9])[0-9]{11})/g; //dinersclub
  var re_jcb = /((?:2131|1800|35d{3})d{11})/g; //jcb

  // now lets put all of those into a nice array so we can loop over it
  var cards = [re_visa, re_amex, re_disc, re_diner, re_jcb];

  // here we are going to check the content type and skip over things that
  // wont contain credit cards like jpegs and such like
  var contenttype = msg.getResponseHeader().getHeader("Content-Type");
  var unwantedfiletypes = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "application/x-shockwave-flash",
    "application/pdf",
  ];

  if (unwantedfiletypes.indexOf("" + contenttype) >= 0) {
    // if we find one of the unwanted headers quit this scan, this saves time and reduces false positives
    return;
  } else {
    // right lets run our scan by looping over all the cards in the array above and testing them against the
    // body of the response
    for (var i = 0; i < cards.length; i++) {
      if (cards[i].test(body)) {
        cards[i].lastindex = 0;
        var foundCard = [];
        var comm;
        while ((comm = cards[i].exec(body))) {
          // perform luhn check this checks to make sure its a valid cc number!
          if (luhncheck(comm[0]) == 0) {
            foundCard.push(comm[0]);
          }
        }
        if (foundCard.length != 0) {
          helper
            .newAlert()
            .setEvidence(foundCard[0])
            .setOtherInfo(`Other instances: ${foundCard.slice(1).toString()}`)
            .setMessage(msg)
            .raise();
        }
      }
    }
  }
}
function luhncheck(value) {
  // this function is based on work done by DiegoSalazar on github (https://gist.github.com/DiegoSalazar)
  var nCheck = 0,
    nDigit = 0,
    bEven = false;
  value = value.replace(/\D/g, "");

  for (var n = value.length - 1; n >= 0; n--) {
    var cDigit = value.charAt(n),
      nDigit = parseInt(cDigit, 10);

    if (bEven) {
      if ((nDigit *= 2) > 9) nDigit -= 9;
    }

    nCheck += nDigit;
    bEven = !bEven;
  }

  // debug here print ("value: " + value + "  lunh: " +nCheck % 10);
  return nCheck % 10;
}
