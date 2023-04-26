// An extender script that adds a simple reverse proxy.

// To where the requests are sent.
var remoteAddress = "example.com"
var remotePort = 80

// The address/port of the proxy.
var proxyAddress = "127.0.0.1"
var proxyPort = 8081

var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender")
var URI = Java.type("org.apache.commons.httpclient.URI")

var extensionNetwork = control.getExtensionLoader().getExtension("ExtensionNetwork")
var proxy

function messageHandler(ctx, msg) {
    if (!ctx.isFromClient()) {
        return
    }

    var requestUri = msg.getRequestHeader().getURI()
    requestUri = new URI(requestUri.getScheme(),
                         requestUri.getUserinfo(),
                         remoteAddress,
                         remotePort,
                         requestUri.getPath())
    msg.getRequestHeader().setURI(requestUri)
}

function install(helper) {
    proxy = extensionNetwork.createHttpProxy(HttpSender.PROXY_INITIATOR, messageHandler)
    proxy.start(proxyAddress, proxyPort)
}

function uninstall(helper) {
    proxy.stop()
}
