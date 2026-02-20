// Standalone scripts have no template.
// They are only evaluated when you run them.
//By Ankush
//This script can export all the spidered/scanned urls from the site tree while automation job is on the go. 
var ZAP_API = 'http://localhost:8080';
var API_KEY = 'q0bhhpgs2oc18k0o';
var PrintWriter = Java.type('java.io.PrintWriter');
var URL = Java.type('java.net.URL');
// sanitization of sanitizationSName function
function sanitizationSName(site) {
  return site.replace(/[^a-zA-Z0-9.-]/g, '_'); // Replace the invalid characters with an underscore as required
}
function request(url, callback) {
  console.log('Making request to: ' + url);
  var connection = new URL(url).openConnection();
  connection.setRequestMethod("GET");
  var response = new java.lang.String(connection.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
  console.log('Received response: ' + response);
  callback(null, {statusCode: connection.getResponseCode()}, response);
}
// Retrieving the site tree from ZAP's API
request(ZAP_API + '/JSON/core/view/sites/?apikey=' + API_KEY, function (error, response, body) {
  if (!error && response.statusCode == 200 ) {
    console.log('Successfully retrieved site tree');
    var sites = JSON.parse(body).sites;
    var completedRequests = 0;
    // Iterate over the site tree
    sites.forEach(function(site) {
      var sanitizedSiteName = sanitizationSName(site);
      // Define a dynamic export location for each site
      var dynamicExportLocation = 'C:\\Users\\12345\\zap\\' + sanitizedSiteName + '_test.txt';
      var writer = new PrintWriter(dynamicExportLocation);
      console.log('Processing site: ' + site);
      // Replace the URL in the request function with the site from the site tree
      request(ZAP_API + '/JSON/core/view/urls/?apikey=' + API_KEY + '&baseurl=' + encodeURIComponent(site), function (error, response, body) {
        if (!error && (response.statusCode == 200 || response.statusCode == 302 || response.statusCode == 404 || response.statusCode == 400)) {
          var urls = JSON.parse(body).urls;
          console.log('Writing URLs for ' + site + ' to the file');
          urls.forEach(function(url) {
            writer.println(url);
          });
        } else {
          console.log('Error retrieving URLs for site: ' + site + ' - ' + error);
        }
        writer.close();
        completedRequests++;
        if (completedRequests === sites.length) {
          console.log('All sites processed');
        }
      });
    });
  } else {
    console.log('Error retrieving site tree: ' + error);
  }
});
