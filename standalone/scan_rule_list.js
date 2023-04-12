// This script gives details about all of the scan rules installed

extAscan = control.getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.ascan.ExtensionActiveScan.NAME);

plugins = extAscan.getPolicyManager().getDefaultScanPolicy().getPluginFactory().getAllPlugin().toArray();

print('Plugin ID\tName\tType\tStatus');
for (var i=0; i < plugins.length; i++) {
  try {
    print(plugins[i].getId()+ '\t' + plugins[i].getName() + '\tActive' + '\t' + plugins[i].getStatus());
  } catch (e) {
    print(e);
  }
}

extPscan = control.getExtensionLoader().getExtension(
        org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.NAME);

plugins = extPscan.getPluginPassiveScanners().toArray();

for (var i=0; i < plugins.length; i++) {
  try {
    print(plugins[i].getPluginId()+ '\t' + plugins[i].getName() + '\tPassive' + '\t' + plugins[i].getStatus());
  } catch (e) {
    print(e);
  }
}
