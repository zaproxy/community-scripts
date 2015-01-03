// html comment finder by freakyclown@gmail.com

function scan(ps, msg, src) {

    alertRisk = 0
    alertReliability = 2
    alertTitle = 'Information Exposure Through HTML Comments (script)'
    alertDesc = 'While adding general comments is very useful, \
some programmers tend to leave important data, such as: filenames related to the web application, old links \
or links which were not meant to be browsed by users, old code fragments, etc.'
    alertSolution = 'Remove comments which have sensitive information about the design/implementation \
of the application. Some of the comments may be exposed to the user and affect the security posture of the \
application.'

    cweId = 615
    wascId = 13

    re = /(\<![\s]*--[-!@#$%^&*:;"'(){}\w\s\/\\[\]]*--[\s]*\>)/g

    url = msg.getRequestHeader().getURI().toString();

    if (msg) {
        body = msg.getResponseBody().toString()
        if (re.test(body)) {
            re.lastIndex = 0
            var foundComments = []
            while (comm = re.exec(body)) {
                foundComments.push(comm[0]);
            }
             ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc, url, '', '', foundComments.toString(), alertSolution,'' , cweId, wascId, msg);
        }
    }
}
