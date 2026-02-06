# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### Added
- Targeted script 'WebCacheDeception.js`
- Standalone script 'PrivateMethodAccess.js'
- Variant script 'AddUrlParams.js'
- Extender script 'ScanMonitor.js'
- Active script 'OpenModelContextProtocolServer.js' - Attempts to detect Model Context Protocol (MCP) servers lacking authentication.

### Changed
- Update minimum ZAP version to 2.16.0 and compile with Java 17.
- Add cautionary note to help and readme.
- Maintenance and documentation changes.
- Active and passive READMEs to include lastest JS script examples.

### Fixed 
- The following scripts were not being loaded as scan rules:
  - active/SSTI.js
  - passive/Mutliple Security Header Check.js

### Removed
- Links to videos which no longer exist.

## [19] - 2024-07-01
### Added
- extender/arpSyndicateSubdomainDiscovery.js - uses the API of [ARPSyndicate's Subdomain Center](https://www.subdomain.center/)
  to find and add subdomains to the Sites Tree.
- passive/JavaDisclosure.js - Passive scan for Java error messages leaks
- httpsender/RsaEncryptPayloadForZap.py - A script that encrypts requests using RSA
- selenium/FillOTPInMFA.js - A script that fills the OTP in MFA
- authentication/KratosApiAuthentication.js - A script to authenticate with Kratos using the API flow
- authentication/KratosBrowserAuthentication.js - A script to authenticate with Kratos using the browser flow

### Changed
- Update minimum ZAP version to 2.15.0.
- Use Prettier to format all JavaScript scripts.
- Update the following scripts to implement the `getMetadata()` function with revised metadata:
  - active/Cross Site WebSocket Hijacking.js
  - active/cve-2019-5418.js
  - active/gof_lite.js
  - active/JWT None Exploit.js
  - active/SSTI.js
  - passive/clacks.js
  - passive/CookieHTTPOnly.js
  - passive/detect_csp_notif_and_reportonly.js
  - passive/detect_samesite_protection.js
  - passive/f5_bigip_cookie_internal_ip.js
  - passive/find base64 strings.js
  - passive/Find Credit Cards.js
  - passive/Find Emails.js
  - passive/Find Hashes.js
  - passive/Find HTML Comments.js
  - passive/Find IBANs.js
  - passive/Find Internal IPs.js
  - passive/find_reflected_params.py
  - passive/HUNT.py
  - passive/Mutliple Security Header Check.js
  - passive/google_api_keys_finder.js
  - passive/JavaDisclosure.js
  - passive/Report non static sites.js
  - passive/RPO.js
  - passive/s3.js
  - passive/Server Header Disclosure.js
  - passive/SQL injection detection.js
  - passive/Telerik Using Poor Crypto.js
  - passive/Upload form discovery.js
  - passive/X-Powered-By_header_checker.js
- httpsender/Alert on Unexpected Content Types.js now checks for common content-types (`json`, `xml`, and `yaml`) more consistently.
- targeted/request_to_xml.js no longer uses deprecated method to show the message in the editor dialogue.

## [18] - 2024-01-29
### Added
- httpsender/RsaSigningForZap.py - A script that signs requests using RSA

### Changed
- Update minimum ZAP version to 2.14.0.
- Remove checks for CFU initiator in HTTP Sender scripts and docs, no longer needed.
- Rename AWS signing script.
- Update descriptions/comments in scripts.
- standalone/Open Fortune 500 websites in a browser.zst - Fix typo in `http://www,pbfenergy.com`

## [17] - 2023-06-28
### Added
- targeted/SQLMapCommandGenerator.js - it will generate and copy sqlmap command based on the request
- encode-decode/JwtDecode.js - Decodes JWTs

### Changed
- Update minimum ZAP version to 2.12.0:
  - Remove compatibility code that provided the singletons (`control` and `model`) in JavaScript scripts, they can now be accessed directly always.
  - Use provided singletons (`control` and `model`) in Python scripts.
  - Use non-deprecated `HttpSender` constructor.
  - extender/Simple Reverse Proxy.js - replace usage of deprecated core classes.
- Remove statements that return the message in HTTP Sender scripts, the message passed as parameter is used/sent always.

## [16] - 2023-03-29
### Added
- httpsender/UpgradeHttp1To2.js - changes all HTTP/1.1 requests to use HTTP/2
- standalone/devTools.js - Tools used to explore objects returned by the Java engine and better plug Nashorn objects into it

### Changed
- encode-decode/double-spacer.js - adapted to the functionality of Encoder 1.0.0.

### Removed
- standalone/Run report.js - no longer working, the old/deprecated class that it used was removed.

### Fixed
- active/User defined attacks.js - correctly escape dot character in some evidence strings.
- targeted/curl_command_generator.js - prevent and warn on local file inclusion when generating the command.
  Thanks to James Kettle (@albinowax) for reporting.

## [15] - 2022-10-02
### Added
- active/RCE.py
- active/SSTI.py
- active/SSTI.js - An active scan script to check for SSTI in 14 different template engines.
- httpfuzzerprocessor/addCacheBusting.js - Fuzzing with cache busting.
- encode-decode
    - README.md - Summary of the script type.
    - double-spacer.js - A script that inserts a space after every character in a string.
- standalone/SecurityCrawlMazeScore.js
- scan-hooks/LogMessagesHook.py and httpsender/LogMessages.js to help debugging, especially in docker.

### Changed
- standalone/enableDebugLogging.js > Updated for more recent logging funtionality.
- Update JS scripts to use passed singleton variables (control, model, view) if available (>= ZAP 2.12.0).
- passive/Server Header Disclosure.js > Updated to check that the Server Header contains something that looks like a semantic version component.

## [14] - 2021-11-01
### Added
- variant/CompoundCookies.js - An input vector script that handles splitting of compound cookies (Issue 6582).
- active/corsair.py > An active scan script to check for CORS related issues.)
- payloadgenerator/securerandom.js > A fuzzer payload generator script that uses Java's SecureRandom as it's source (related to issue 6892).
- active/bxss.py > an active scan script for inject blind xss payloads to the parameters

## [13] - 2021-10-14
### Fixed
- targeted/cve-2021-41773-apache-path-trav.js - Set path as escaped so that it's handled properly, set pluginid properly.

## [12] - 2021-10-07
### Added
- authentication/OfflineTokenRefresh.js - refresh oauth2 offline tokens
- httpsender/AddBearerTokenHeader.js - refresh oauth2 offline tokens
- targeted/WordPress Username Enumeration.js - A targeted script to check for WordPress Username Enumeration via author archives
- targeted/cve-2021-41773-apache-path-trav.js - an active scan script to test for Apache 2.4.49 CVE-2021-41773 path traversal.

### Changed
- Update minimum ZAP version to 2.11.0.

## [11] - 2021-09-07
### Added
- active/Cross Site WebSocket Hijacking.js > an active scan for Cross-Site WebSocket Hijacking vulnerability
- targeted/cve-2021-22214.js > A targeted script to check for Unauthorised SSRF on GitLab - CVE 2021-22214
- httpsender/full-session-n-csrf-nashorn.js > full session and csrf token management.
- httpfuzzerprocessor/unexpected_responses.js > compare response codes to a (pass/fail) regex and generate alerts
- targeted/dns-email-spoofing > Check if DMARC / SPF policies are configured on a domain.
- httpsender/add-more-headers.js > Add caller-specified headers to all requests.

### Changed
- Update links in READMEs.
- Update JavaDoc links to latest version.

## [10] - 2021-06-11

### Added
- standalone/load_context_from_burp -> import context from burp config file
- Passive scan script for finding potential s3 Bucket URLs
- payloadprocessor/to-hex.js > string to hex payload script.
- selenium and session scripts.
- httpfuzzerprocessor/random_x_forwarded_for_ip.js > Set 'X-Forwarded-For' to a random IP value.
- httpfuzzerprocessor/randomUserAgent.js > Set 'User-Agent' to a random user-agent.
- Add the following Payload Processor scripts ported from SQLMap:
  - apostrophemask
  - apostrophenullencode
  - chardoubleencode
  - charencode
  - charunicodeencode
  - equaltolike
  - lowercase
  - percentage
  - randomcase
  - space2comments
- Add Google API keys finder script

### Changed
- Update minimum ZAP version to 2.10.0.
- Rename reliability to confidence.
- standalone/enableDebugLogging.js > use new Log4j 2 APIs.
- standalone/window_creation_template.js > no longer extend `AbstractFrame`.
- httpsender/Alert on HTTP Response Code Errors.js and Alert on Unexpected Content Types.js:
  - Check if messages being analyzed are globally excluded or not;
  - Ignore check for update messages;
  - Include more expected content types.
- httpsender/aws-signing-for-owasp-zap.py > read AWS environment variables for default values.
- active/TestInsecureHTTPVerbs.py and passive/HUNT.py > correct links to OWASP site.

### Removed
- standalone/loadListInGlobalVariable.js > superseded by core functionality, `ScriptVars.setGlobalCustomVar(...)` and `getGlobalCustomVar(...)`.

### Fixed
- extender/HTTP Message Logger.js > fix typo in Integer constant.

## [9] - 2020-01-30

### Added
- Add repo URL, shown in the marketplace and Manage Add-ons dialogue.
- active/cve-2019-5418.js > An active scanner for Ruby on Rails Accept header content disclosure issue.
- active/JWT None Exploit.js > Checks if the application's JWT implementation allows the usage of the 'none' algorithm.
- authentication/DjangoAuthentication.js > Django authentication script.
- authentication/GetsWithRedirectThenPost.js > An authentication script that follows GET redirects and then submits a POST with the authentication credentials.
- extender/Simple Reverse Proxy.js > Adds a simple reverse proxy.
- extender/ZAP onEvent Handler.js > An example for how to listen for internal ZAP events.
- httpsender/add-extra-headers.js > Adds encountered 'extra' headers to all requests.
- httpsender/aws-signing-for-owasp-zap.py > Signs requests to AWS.
- httpsender/fingerprinter.js > Logs MD5s of responses.
- httpsender/greenbone-maintain-auth.js > An auth helper script for OpenVAS Greenbone web interface.
- httpsender/inject-xss.js > Injects XSS payloads into JSON responses.
- httpsender/juice-shop-maintain-auth.js > An auth helper script for OWASP JuiceShop.
- httpsender/keep-cookies-going.js > An auth helper script.
- httpsender/maintain-jwt.js > Tracks JWTs and updates Authorization bearer headers.
- passive/Find IBANs.js > Finds IBANs in HTTP response bodies.
- passive/HUNT.py > Merge of existing HUNT scripts.
- proxy/Drop requests by response code.js > Drops requests that have a given response code.
- standalone/scan_rule_list.js > Lists details from both active and passive scan rules.
- standalone/Split download extract.rb > Concatenates split file downloads.

### Changed
- Change info URL to link to the online help page.
- Updated to target ZAP 2.9

### Removed
- The following scripts were merged into a new script `HUNT.py`:
  - passive/HUNT - Debug & Logic Parameters.py
  - passive/HUNT - File Inclusion.py
  - passive/HUNT - IDOR.py
  - passive/HUNT - RCE.py
  - passive/HUNT - SQLi.py
  - passive/HUNT - SSRF.py
  - passive/HUNT - SSTI.py

### Fixed
- Fix links to source files in zaproxy repo.

## 8 - 2018-06-19

- Update from community-scripts repo.

## 7 - 2018-05-07

- Update from community-scripts repo.

## 6 - 2018-02-06

- Update from community-scripts repo.

## 5 - 2017-11-28

- Updated for 2.7.0.

## 4 - 2017-10-17

- Updated with the latest scripts for 2.6.0
- Stop the scripts from being registered twice

## 3 - 2016-06-02

- Updated with the latest scripts for 2.5.0

## 2 - 2016-02-17

- Fixed bug which prevents ZAP configs from being saved correctly

## 1 - 2016-02-12

- First packaged version

[Unreleased]: https://github.com/zaproxy/community-scripts/compare/v19...HEAD
[19]: https://github.com/zaproxy/community-scripts/compare/v18...v19
[18]: https://github.com/zaproxy/community-scripts/compare/v17...v18
[17]: https://github.com/zaproxy/community-scripts/compare/v16...v17
[16]: https://github.com/zaproxy/community-scripts/compare/v15...v16
[15]: https://github.com/zaproxy/community-scripts/compare/v14...v15
[14]: https://github.com/zaproxy/community-scripts/compare/v13...v14
[13]: https://github.com/zaproxy/community-scripts/compare/v12...v13
[12]: https://github.com/zaproxy/community-scripts/compare/v11...v12
[11]: https://github.com/zaproxy/community-scripts/compare/v10...v11
[10]: https://github.com/zaproxy/community-scripts/compare/v9...v10
[9]: https://github.com/zaproxy/community-scripts/compare/7278617af4bd1bc3d8db41c00a0437bf78ba6e51...v9
