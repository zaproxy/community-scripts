// This script gives details about all of the active scan rules installed

// The following handles differences in printing between Java 7's Rhino JS engine
// and Java 8's Nashorn JS engine
if (typeof println == 'undefined') this.println = print;

extAscan = org.parosproxy.paros.control.Control.getSingleton().
    getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.ascan.ExtensionActiveScan.NAME);

plugins = extAscan.getPolicyManager().getDefaultScanPolicy().getPluginFactory().getAllPlugin().toArray();

print('\n');

for (var i=0; i < plugins.length; i++) {
  try {
    print ('Plugin ID: ' + plugins[i].getId());
    print ('Name: ' + plugins[i].getName());
    print ('Desc: ' + plugins[i].getDescription());
    print ('Risk: ' + plugins[i].getRisk());
    print ('Soln: ' + plugins[i].getSolution());
    print ('Ref:  ' + plugins[i].getReference());
    print ('CWE:  ' + plugins[i].getCweId());
    print ('WASC:  ' + plugins[i].getWascId());
    print ('');
  } catch (e) {
    print (e);
  }
}
