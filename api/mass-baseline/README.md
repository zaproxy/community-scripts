# Mass Baseline scan

This directory contains scripts that allow you to run the [ZAP Baseline Scan](https://www.zaproxy.org/docs/docker/baseline-scan/) against a series of target URLs. It also (by default) publishes the results to the wiki that the scripts belong to.

In order to use these scripts you will need to:

* Change the sites listed in [mass-baseline.sh](mass-baseline.sh)
* Change the relevant user and repo details in [mass-baseline.sh](mass-baseline.sh)
* Build a docker image (see below)
* Run the docker image, setting the credentials for your user (see below) if you want to upload the results to your repo wiki

To create the docker container
-----
Run a command like:

`docker build -t your-user/mass-baseline -f docker-wrapper .`

To run the mass baseline scan
----
Run a command like:

`docker run -u zap -i -t your-user/mass-baseline mass-baseline.sh`

If you want to write to your wiki then you will need to set the $baselinecreds env var to a suitable value, for example a Personal Access Token.
If you are running this via Jenkins then you can use Jenkins credentials.
