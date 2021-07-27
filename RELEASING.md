# Release

The following steps should be followed to release the add-on:
 1. Run the workflow [Prepare Release Add-on](https://github.com/zaproxy/community-scripts/actions/workflows/prepare-release-add-on.yml),
    to prepare the release. It creates a pull request updating the version and changelog;
 2. Merge the pull request.

After merging the pull request the [Release Add-on](https://github.com/zaproxy/community-scripts/actions/workflows/release-add-on.yml) workflow
will create the tag, create the release, trigger the update of the marketplace, and create a pull request preparing the next development iteration.

## Localized Resources

The resources that require localization (e.g. `Messages.properties`, help pages) are uploaded to the OWASP ZAP projects in
[Crowdin](https://crowdin.com/) when the add-on is released, if required (for pre-translation) the resources can be uploaded manually at anytime
by running the workflow [Crowdin Upload Files](https://github.com/zaproxy/community-scripts/actions/workflows/crowdin-upload-files.yml).

The resulting localized resources are added/updated in the repository periodically (through a workflow in the
[zap-admin repository](https://github.com/zaproxy/zap-admin/)).
