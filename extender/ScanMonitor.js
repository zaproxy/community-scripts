// This script monitors the active scanner and ends the scan if certain conditions are met.
// By default it just ends the scan for high:
//  * Connection failures
//  * Authentication failures
//  * Response times
// You can easily chane the script to end the scan for other conditions, such as high 4xx / 5xx response codes,
// but these tend to be application specific so they are not enabled by default.

var SessionStructure = Java.type("org.zaproxy.zap.model.SessionStructure");
var Timer = Java.type("java.util.Timer");
var TimerTask = Java.type("java.util.TimerTask");
var URI = Java.type("org.apache.commons.httpclient.URI");

var extAscan = control.getExtensionLoader().getExtension("ExtensionActiveScan");
var inMemoryStats = control
  .getExtensionLoader()
  .getExtension("ExtensionStats")
  .getInMemoryStats();

var timer = new Timer();
var timerSecs = 10 * 1000; // Check every 10 secs

// Set to true to see the stats reported live
var log = false;

function install(helper) {
  timer.scheduleAtFixedRate(
    new TimerTask() {
      run: function () {
        runchecks();
      },
    },
    0,
    timerSecs
  );
}

function getStat(site, stat) {
  var val =
    site == null
      ? inMemoryStats.getStat(stat)
      : inMemoryStats.getStat(site, stat);
  return val == null ? 0 : val;
}

// Response times are recorded in logarithmic millisec time slices
function getLongRespStats(site) {
  return (
    getStat(site, "stats.responseTime.16384") +
    getStat(site, "stats.responseTime.32768") +
    getStat(site, "stats.responseTime.65536")
  );
}

function runchecks() {
  if (log) print("Running checks..");
  ascans = extAscan.getActiveScans();
  ascans.forEach((as, i) => {
    // For the full set of stats that can be monitored see https://www.zaproxy.org/docs/internal-statistics/
    var site = SessionStructure.getHostName(new URI(as.getDisplayName(), true));
    if (log) print("Site: " + site);
    // Connection failures are global rather than site specific
    var connFails = getStat(null, "stats.network.send.failure");
    // All HTTP response codes are recorded, so you can add checks for 401, 403 etc etc
    var stats401 = getStat(site, "stats.code.401");
    var stats500 = getStat(site, "stats.code.500");
    // Auth fails are only relevant for authenticated scans
    var authFails = getStat(site, "stats.auth.failure");
    var longResp = getLongRespStats(site);

    if (log) {
      print("  401 resps:\t" + stats401);
      print("  500 resps:\t" + stats500);
      print("  conn fails:\t" + connFails);
      print("  auth fails:\t" + authFails);
      print("  long resps:\t" + longResp);
    }
    // Change this test to meet your requirements as needed.
    if (connFails > 1000 || authFails > 1000 || longResp > 1000) {
      if (log) print("Stopping ascan " + site);
      as.stopScan();
    }
  });
}

function uninstall(helper) {
  timer.cancel();
}
