/**
 * This script uses the API of ARPSyndicate's Subdomain Center (https://www.subdomain.center/) to
 * find and add subdomains to the Sites Tree. When it is enabled, it runs automatically for each
 * new domain added to the Sites Tree.
 */

const HistoryReference = Java.type(
  "org.parosproxy.paros.model.HistoryReference"
);
const HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
const HttpMessage = Java.type("org.parosproxy.paros.network.HttpMessage");
const URI = Java.type("org.apache.commons.httpclient.URI");
const requestedSubdomains = [];
const sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

function consumer(event) {
  if (event.getEventType() != "site.added") return;
  try {
    const siteNode = event.getTarget().getStartNode();
    const host = siteNode.getHistoryReference().getURI().getHost();
    if (requestedSubdomains.indexOf(host) != -1) {
      // Don't run for subdomain nodes created by this script
      return;
    }
    const apiUri = new URI(
      `https://api.subdomain.center/?domain=${host}`,
      true
    );
    const apiMsg = new HttpMessage(apiUri);
    sender.sendAndReceive(apiMsg);
    const subdomains = JSON.parse(apiMsg.getResponseBody().toString());
    subdomains.forEach(function (subdomain) {
      const uri = new URI(`https://${subdomain}`, true);
      const msg = new HttpMessage(uri);
      const extHistory = control
        .getExtensionLoader()
        .getExtension("ExtensionHistory");
      try {
        sender.sendAndReceive(msg);
        const href = new HistoryReference(
          model.getSession(),
          HistoryReference.TYPE_ZAP_USER,
          msg
        );
        extHistory.addHistory(href);
        requestedSubdomains.push(subdomain);
      } catch (err) {
        print(
          `Failed to send a request to "https://${subdomain}": ${err.getMessage()}.`
        );
      }
    });
  } catch (err) {
    print(
      `There was an error while trying to get subdomains using Subdomain Center: ${err}`
    );
  }
}

function install(helper) {
  org.zaproxy.zap.ZAP.getEventBus().registerConsumer(
    consumer,
    "org.parosproxy.paros.model.SiteMapEventPublisher"
  );
}

function uninstall(helper) {
  org.zaproxy.zap.ZAP.getEventBus().unregisterConsumer(consumer);
}
