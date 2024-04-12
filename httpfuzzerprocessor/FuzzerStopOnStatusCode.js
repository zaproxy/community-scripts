var STATUS_CODE_PARAM = "Status Code";

function processMessage(utils, message) {}

function processResult(utils, fuzzResult) {
  if (
    fuzzResult.getHttpMessage().getResponseHeader().getStatusCode() ==
    utils.getParameters().get(STATUS_CODE_PARAM)
  )
    utils.stopFuzzer();
  return true;
}

function getRequiredParamsNames() {
  return [STATUS_CODE_PARAM];
}
