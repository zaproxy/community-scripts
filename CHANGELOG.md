# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- payloadprocessor/to-hex.js > string to hex payload script.
- selenium and session scripts.
- httpfuzzerprocessor/random_x_forwarded_for_ip.js > Set 'X-Forwarded-For' to a random IP value.
- httpfuzzerprocessor/randomUserAgent.js > Set 'User-Agent' to a random user-agent.

### Changed
- Update minimum ZAP version to 2.10.0.
- standalone/enableDebugLogging.js > use new Log4j 2 APIs.
- standalone/window_creation_template.js > no longer extend `AbstractFrame`.

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

[Unreleased]: https://github.com/zaproxy/community-scripts/compare/v9...HEAD
[9]: https://github.com/zaproxy/community-scripts/compare/7278617af4bd1bc3d8db41c00a0437bf78ba6e51...v9
