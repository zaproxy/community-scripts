# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Added
- active/cve-2019-5418.js > An active scanner for Ruby on Rails Accept header content disclosure issue.
- authentication/DjangoAuthentication.js > Django authentication script.
- standalone/scan_rule_list.js > Lists details from both active and passive scan rules.
- standalone/Split download extract.rb > Add script to concatenate split file downloads
- extender/ZAP onEvent Handler.js > An example for how to listen for internal ZAP events
- httpsender/add-extra-headers.js > Adds encountered 'extra' headers to all requests.
- httpsender/fingerprinter.js > Logs MD5s of responses.
- httpsender/greenbone-maintain-auth.js > An auth helper script for OpenVAS Greenbone web interface.
- httpsender/inject-xss.js > Injects XSS payloads into JSON responses.
- httpsender/juice-shop-maintain-auth.js > An auth helper script for OWASP JuiceShop.
- httpsender/keep-cookies-going.js > An auth helper script.
- httpsender/maintain-jwt.js > Tracks JWTs and updates Authorization bearer headers.

### Changed
- Misc maintenance changes.
- Maintenance changes to target ZAP 2.8.

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

