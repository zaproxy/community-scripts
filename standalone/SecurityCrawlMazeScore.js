// Score ZAP against Google Security Crawl Maze
//
// You will need to have run one or both of the ZAP spiders against https://security-crawl-maze.app/

// Expected results sourced from:
// https://raw.githubusercontent.com/google/security-crawl-maze/master/blueprints/utils/resources/expected-results.json

var expectedResults = [
  "/css/font-face.found",
  "/headers/content-location.found",
  "/headers/link.found",
  "/headers/location.found",
  "/headers/refresh.found",
  "/html/doctype.found",
  "/html/manifest.found",
  "/html/body/background.found",
  "/html/body/a/href.found",
  "/html/body/a/ping.found",
  "/html/body/audio/src.found",
  "/html/body/applet/archive.found",
  "/html/body/applet/codebase.found",
  "/html/body/blockquote/cite.found",
  "/html/body/embed/src.found",
  "/html/body/form/action-get.found",
  "/html/body/form/action-post.found",
  "/html/body/form/button/formaction.found",
  "/html/body/frameset/frame/src.found",
  "/html/body/iframe/src.found",
  "/html/body/iframe/srcdoc.found",
  "/html/body/img/dynsrc.found",
  "/html/body/img/lowsrc.found",
  "/html/body/img/longdesc.found",
  "/html/body/img/src-data.found",
  "/html/body/img/src.found",
  "/html/body/img/srcset1x.found",
  "/html/body/img/srcset2x.found",
  "/html/body/input/src.found",
  "/html/body/isindex/action.found",
  "/html/body/map/area/ping.found",
  "/html/body/object/data.found",
  "/html/body/object/codebase.found",
  "/html/body/object/param/value.found",
  "/html/body/script/src.found",
  "/html/body/svg/image/xlink.found",
  "/html/body/svg/script/xlink.found",
  "/html/body/table/background.found",
  "/html/body/table/td/background.found",
  "/html/body/video/src.found",
  "/html/body/video/poster.found",
  "/html/head/profile.found",
  "/html/head/base/href.found",
  "/html/head/comment-conditional.found",
  "/html/head/import/implementation.found",
  "/html/head/link/href.found",
  "/html/head/meta/content-csp.found",
  "/html/head/meta/content-pinned-websites.found",
  "/html/head/meta/content-reading-view.found",
  "/html/head/meta/content-redirect.found",
  "/html/misc/url/full-url.found",
  "/html/misc/url/path-relative-url.found",
  "/html/misc/url/protocol-relative-url.found",
  "/html/misc/url/root-relative-url.found",
  "/html/misc/string/dot-dot-slash-prefix.found",
  "/html/misc/string/dot-slash-prefix.found",
  "/html/misc/string/url-string.found",
  "/html/misc/string/string-known-extension.pdf",
  "/javascript/misc/comment.found",
  "/javascript/misc/string-variable.found",
  "/javascript/misc/string-concat-variable.found",
  "/javascript/frameworks/angular/event-handler.found",
  "/javascript/frameworks/angular/router-outlet.found",
  "/javascript/frameworks/angularjs/ng-href.found",
  "/javascript/frameworks/polymer/event-handler.found",
  "/javascript/frameworks/polymer/polymer-router.found",
  "/javascript/frameworks/react/route-path.found",
  "/javascript/frameworks/react/index.html/search.found",
  "/misc/known-files/robots.txt.found",
  "/misc/known-files/sitemap.xml.found",
];

function findNode(scheme, path) {
  var uri = new URI(scheme + "://" + target + "/test" + path, true);
  var n = siteTree.findNode(uri);
  if (n == null) {
    // Find parent then loop through child nodes checking for the URL path
    var parent = siteTree.findClosestParent(uri);
    if (parent) {
      for (var j = 0; j < parent.getChildCount(); j++) {
        var child = parent.getChildAt(j);
        if (child.getHierarchicNodeName().indexOf(path) > 0) {
          n = child;
          break;
        }
      }
    }
  }
  return n;
}

var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference");
var URI = Java.type("org.apache.commons.httpclient.URI");

var found = 0;
var foundStandard = 0;
var foundAjax = 0;
var total = expectedResults.length;

var target = "security-crawl-maze.app";
var siteTree = model.getSession().getSiteTree();

print("Security crawl Maze Results\t\t\tScheme\tStandard\tAjax");
print("----\t\t\t\t---\t---");

for (var i in expectedResults) {
  var res = expectedResults[i];
  var scheme = "http";
  var node = findNode(scheme, res);
  if (!node) {
    scheme = "https";
    node = findNode(scheme, res);
  }

  print(res);
  var spiderResult = "FAIL";
  var ajaxResult = "FAIL";
  if (node) {
    found++;
    if (node.hasHistoryType(HistoryReference.TYPE_SPIDER)) {
      spiderResult = "Pass";
      foundStandard++;
    }
    if (node.hasHistoryType(HistoryReference.TYPE_SPIDER_AJAX)) {
      ajaxResult = "Pass";
      foundAjax++;
    }
  } else {
    scheme = "";
  }
  print("\t\t\t\t" + scheme + "\t" + spiderResult + "\t" + ajaxResult);
}

print("Tests:\t" + total);
print("Total Passes:\t" + found);
print("Standard Passes: " + foundStandard);
print("Ajax Passes: " + foundAjax);
print("Fails:\t" + (total - found));
print("Score:\t" + Math.round((found * 100) / total) + "%");
