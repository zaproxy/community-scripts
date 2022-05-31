// An extender script that adds a simple reverse proxy.
// Requires a ZAP version greater than 2.7.0.

var control, model
if (!control) control = Java.type("org.parosproxy.paros.control.Control").getSingleton()
if (!model) model = Java.type("org.parosproxy.paros.model.Model").getSingleton()

// To where the requests are sent.
var remoteAddress = "example.com"
var remotePort = 80

// The address/port of the proxy.
var proxyAddress = "127.0.0.1"
var proxyPort = 8081

var ProxyServer = Java.type("org.parosproxy.paros.core.proxy.ProxyServer")
var ProxyListener = Java.type("org.parosproxy.paros.core.proxy.ProxyListener")
var ZapXmlConfiguration = Java.type("org.zaproxy.zap.utils.ZapXmlConfiguration")
var URI = Java.type("org.apache.commons.httpclient.URI")

var extLoader = control.getExtensionLoader()
var proxy

function install(helper) {
    proxy = new ProxyServer("Proxy");
    proxy.getProxyParam().load(new ZapXmlConfiguration());
    var proxyParam = proxy.getProxyParam();
    proxyParam.setAlwaysDecodeGzip("false");
    proxyParam.setBehindNat(false);
    proxyParam.setRemoveUnsupportedEncodings(true);

    proxy.setConnectionParam(model.getOptionsParam().getConnectionParam());
    proxy.setEnableApi(false);

    extLoader.addProxyServer(proxy)

    proxy.addProxyListener(new ProxyListener() {

        onHttpRequestSend: function(msg) {
            var requestUri = msg.getRequestHeader().getURI()
            requestUri = new URI(requestUri.getScheme(),
                                 requestUri.getUserinfo(),
                                 remoteAddress,
                                 remotePort,
                                 requestUri.getPath())
            msg.getRequestHeader().setURI(requestUri)
            return true
        },

        onHttpResponseReceive: function(msg) { return true },
        getArrangeableListenerOrder: function() { return 0 }
    })

    proxy.startServer(proxyAddress, proxyPort, false);
}

function uninstall(helper) {
    proxy.stopServer()
    extLoader.removeProxyServer(proxy)
}
