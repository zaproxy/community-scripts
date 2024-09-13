import org.gradle.api.internal.provider.TransformBackedProvider
import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.internal.model.ProjectInfo
import org.zaproxy.gradle.addon.internal.model.ReleaseState
import org.zaproxy.gradle.addon.internal.tasks.GenerateReleaseStateLastCommit
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.11.0"
    id("org.zaproxy.crowdin") version "0.4.0"
    id("com.diffplug.spotless")
    id("com.github.node-gradle.node") version "7.0.2"
    id("org.zaproxy.common")
}

description = "Useful ZAP scripts written by the ZAP community."

val scriptsDir = layout.buildDirectory.dir("scripts")

zapAddOn {
    addOnId.set("communityScripts")
    addOnName.set("Community Scripts")
    zapVersion.set("2.15.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    releaseLink.set("https://github.com/zaproxy/community-scripts/compare/v@PREVIOUS_VERSION@...v@CURRENT_VERSION@")
    unreleasedLink.set("https://github.com/zaproxy/community-scripts/compare/v@CURRENT_VERSION@...HEAD")

    manifest {
        author.set("ZAP Community")
        url.set("https://www.zaproxy.org/docs/desktop/addons/community-scripts/")
        repo.set("https://github.com/zaproxy/community-scripts/")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
        files.from(scriptsDir)
    }
}

crowdin {
    credentials {
        token.set(System.getenv("CROWDIN_AUTH_TOKEN"))
    }

    configuration {
        file.set(file("gradle/crowdin.yml"))
        tokens.set(mutableMapOf("%addOnId%" to zapAddOn.addOnId.get()))
    }
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    testImplementation("commons-io:commons-io:2.16.1")
    testImplementation("org.assertj:assertj-core:3.26.0")
    testImplementation("org.apache.commons:commons-lang3:3.14.0")

    // The following versions should match the ones of the add-ons.
    testImplementation("org.codehaus.groovy:groovy-all:3.0.14")
    val graalJsVersion = "22.3.3"
    testImplementation("org.graalvm.js:js:$graalJsVersion")
    testImplementation("org.graalvm.js:js-scriptengine:$graalJsVersion")
    testImplementation("org.jruby:jruby-complete:1.7.4")
    testImplementation("org.zaproxy:zest:0.21.0")
    testImplementation("org.python:jython-standalone:2.7.2")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

var scriptTypes =
    listOf(
        "active",
        "authentication",
        "encode-decode",
        "extender",
        "httpfuzzerprocessor",
        "httpsender",
        "passive",
        "payloadgenerator",
        "payloadprocessor",
        "proxy",
        "selenium",
        "sequence",
        "session",
        "standalone",
        "targeted",
        "variant",
        "websocketfuzzerprocessor",
        "websocketpassive",
    )

val syncScriptsDirTask by tasks.creating(Sync::class) {
    into(scriptsDir.get().dir(project.name))

    scriptTypes.forEach {
        from(it) {
            into(it)
        }
    }
}

tasks.named(AddOnPlugin.GENERATE_MANIFEST_TASK_NAME) {
    dependsOn(syncScriptsDirTask)
}

java {
    val javaVersion = JavaVersion.VERSION_11
    sourceCompatibility = javaVersion
    targetCompatibility = javaVersion
}

sourceSets["main"].output.dir(mapOf("builtBy" to syncScriptsDirTask), scriptsDir)

node {
    version = "20.12.1"
    download = true
}

spotless {
    kotlinGradle {
        ktlint()
    }
    javascript {
        target("**/*.js")
        targetExclude("extender/HTTP Message Logger.js", "extender/ScanMonitor.js", "standalone/domainFinder.js")
        // get the npm executable path from gradle-node-plugin
        val npmDir = (tasks.named("npmSetup").get().property("npmDir") as TransformBackedProvider<*, *>).get().toString()
        val npmExecutable = if (System.getProperty("os.name").lowercase().contains("windows")) "/npm.cmd" else "/bin/npm"
        prettier().npmExecutable(npmDir.plus(npmExecutable))
    }
}

tasks.named("spotlessJavascript").configure {
    dependsOn("nodeSetup", "npmSetup")
}

val projectInfo = ProjectInfo.from(project)
val generateReleaseStateLastCommit by tasks.registering(GenerateReleaseStateLastCommit::class) {
    projects.set(listOf(projectInfo))
}

repositories {
    mavenCentral()
}

val releaseAddOn by tasks.registering {
    if (ReleaseState.read(projectInfo).isNewRelease()) {
        dependsOn("createRelease")
        dependsOn("handleRelease")
        dependsOn("createPullRequestNextDevIter")
        dependsOn("crowdinUploadSourceFiles")
    }
}
