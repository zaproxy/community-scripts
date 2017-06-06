// CreditCard Finder by freakyclown@gmail.com

function scan(ps, msg, src) {
    url = msg.getRequestHeader().getURI().toString();
    body = msg.getResponseBody().toString()
    alertRisk = [0, 1, 2, 3] //1=informational, 2=low, 3=medium, 4=high
    alertReliability = [0, 1, 2, 3, 4] //0=fp,1=low,2=medium,3=high,4=confirmed
    alertTitle = ["Credit Card Number Disclosed (script)",
        ""
    ]
    alertDesc = ["A Credit Card number was discovered.",
        ""
    ]
    alertSolution = ["why are you showing Credit and debit card numbers?",
        ""
    ]
    cweId = [0, 1]
    wascId = [0, 1]



    // regex must appear within /( and )/g


    re_visa = /([3-5][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})/g //visa or mastercard
    re_amex = /(3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5})/g //amex
    re_disc = /(6011[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})/g //discovery
    re_diner = /(3(?:0[0-5]|[68][0-9])[0-9]{11})/g //dinersclub
    re_jcb = /((?:2131|1800|35d{3})d{11})/g //jcb



    if (msg) {
        if (re_visa.test(body)) {
            re_visa.lastIndex = 0
            var foundVisa = []
            while (comm = re_visa.exec(body)) {
                foundVisa.push(comm[0]);
            }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundVisa.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
        }

        if (re_amex.test(body)) {
            re_amex.lastIndex = 0
            var foundAmex = []
            while (comm = re_amex.exec(body)) {
                foundAmex.push(comm[0]);
            }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundAmex.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
        }
        if (re_disc.test(body)) {
            re_disc.lastIndex = 0
            var foundDisc = []
            while (comm = re_disc.exec(body)) {
                foundDisc.push(comm[0]);
            }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundDisc.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
        }

        if (re_diner.test(body)) {
            re_diner.lastIndex = 0
            var foundDiner = []
            while (comm = re_diner.exec(body)) {
                foundDiner.push(comm[0]);
            }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundDiner.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
        }

        if (re_jcb.test(body)) {
            re_jcb.lastIndex = 0
            var foundJCB = []
            while (comm = re_jcb.exec(body)) {
                foundJCB.push(comm[0]);
            }
            ps.raiseAlert(alertRisk[3], alertReliability[2], alertTitle[0], alertDesc[0], url, '', '', foundJCB.toString(), alertSolution[0], '', cweId[0], wascId[0], msg);
        }

    }



}
