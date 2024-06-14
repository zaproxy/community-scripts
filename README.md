community-scripts
=================

A collection of ZAP scripts provided by the community, i.e. you lot :)

The easiest way to use this repo in ZAP is to install the 'Community Scripts' add-on from the ZAP Marketplace.

If you might want to contribute to the repo then you can also clone it to a local directory and then add that to ZAP using the Options / Scripts screen.

Please upload your scripts via pull requests!

For more information on ZAP scripts:
* Display the [`Scripts Tab`](https://www.zaproxy.org/docs/desktop/addons/script-console/tree/) by `View->Show Tab->Scripts Tab` to manage the scripts.
* https://www.zaproxy.org/docs/desktop/addons/script-console/
* https://github.com/zaproxy/zaproxy/wiki/InternalScripting
 
To discuss any aspect of ZAP scripting please join the zaproxy-scripts group: http://groups.google.com/group/zaproxy-scripts

**Note**: For .py scripts to be visible, you must have the [Python Scripting](https://www.zaproxy.org/docs/desktop/addons/python-scripting/) add-on installed. Same with Ruby, Kotlin, etc.

Please ensure that scripts submitted have the correct extension for the language they are written in.

All scripts in the repo are released under the Apache v2.0 licence.

You may obtain a copy of the License at  http://www.apache.org/licenses/LICENSE-2.0 

By submitting your scripts to this repo you are releasing them under the Apache v2.0 licence, however you may optionally also release them under more lenient licenses via comments in the scripts.

## Building

This project uses Gradle to build the ZAP add-on, simply run:

    ./gradlew build

in the main directory of the project, the add-on will be placed in the directory `build/zapAddOn/bin/`.

## Official Videos

* [ZAP In Ten: Introduction to Scripting](https://play.sonatype.com/watch/7gR4qYzUZ686wEDMBfxGdf) (9:33)
* [ZAP Deep Dive: Scripting ZAP](https://www.youtube.com/watch?v=ujL6rH6nVXI) (28:34)

Note that there are videos for some of the specific script types linked from the relevant READMEs.
