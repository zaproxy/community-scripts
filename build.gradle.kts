import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.internal.model.ProjectInfo
import org.zaproxy.gradle.addon.internal.model.ReleaseState
import org.zaproxy.gradle.addon.internal.tasks.GenerateReleaseStateLastCommit
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.8.0"
    id("org.zaproxy.crowdin") version "0.1.0"
    id("com.diffplug.spotless") version "5.12.1"
}

repositories {
    mavenCentral()
}

description = "Useful ZAP scripts written by the ZAP community."

val scriptsDir = layout.buildDirectory.dir("scripts")

zapAddOn {
    addOnId.set("communityScripts")
    addOnName.set("Community Scripts")
    zapVersion.set("2.11.0")
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

val jupiterVersion = "5.7.0-M1"

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:$jupiterVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$jupiterVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$jupiterVersion")

    testImplementation("commons-io:commons-io:2.6")
    testImplementation("org.assertj:assertj-core:3.11.0")
    testImplementation("org.apache.commons:commons-lang3:3.8")

    // The following versions should match the ones of the add-ons.
    testImplementation("org.codehaus.groovy:groovy-all:2.4.14")
    testImplementation("org.jruby:jruby-complete:1.7.4")
    testImplementation("org.mozilla:zest:0.14.0")
    testImplementation("org.python:jython-standalone:2.7.1")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs = listOf("-Xlint:all", "-Xlint:-options", "-Werror")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

var scriptTypes = listOf(
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
        "websocketpassive")

val syncScriptsDirTask by tasks.creating(Sync::class) {
    into(scriptsDir.get().dir(project.name))

    scriptTypes.forEach {
        from(it) {
            into(it)
        }
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

sourceSets["main"].output.dir(mapOf("builtBy" to syncScriptsDirTask), scriptsDir)

spotless {
    java {
        licenseHeaderFile("$rootDir/gradle/spotless/license.java")

        googleJavaFormat("1.7").aosp()
    }

    kotlinGradle {
        ktlint()
    }
}

val projectInfo = ProjectInfo.from(project)
val generateReleaseStateLastCommit by tasks.registering(GenerateReleaseStateLastCommit::class) {
    projects.set(listOf(projectInfo))
}

val releaseAddOn by tasks.registering {
    if (ReleaseState.read(projectInfo).isNewRelease()) {
        dependsOn("createRelease")
        dependsOn("handleRelease")
        dependsOn("createPullRequestNextDevIter")
        dependsOn("crowdinUploadSourceFiles")
    }
}
