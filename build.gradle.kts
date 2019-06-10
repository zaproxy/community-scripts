import org.zaproxy.gradle.addon.AddOnPlugin
import org.zaproxy.gradle.addon.AddOnStatus
import org.zaproxy.gradle.addon.misc.ConvertMarkdownToHtml
import org.zaproxy.gradle.addon.misc.CreateGitHubRelease
import org.zaproxy.gradle.addon.misc.ExtractLatestChangesFromChangelog

plugins {
    `java-library`
    id("org.zaproxy.add-on") version "0.2.0"
    id("com.diffplug.gradle.spotless") version "3.15.0"
}

repositories {
    mavenCentral()
}

version = "9"
description = "Useful ZAP scripts written by the ZAP community."

val scriptsDir = layout.buildDirectory.dir("scripts")

zapAddOn {
    addOnId.set("communityScripts")
    addOnName.set("Community Scripts")
    zapVersion.set("2.8.0")
    addOnStatus.set(AddOnStatus.ALPHA)

    releaseLink.set("https://github.com/zaproxy/community-scripts/compare/v@PREVIOUS_VERSION@...v@CURRENT_VERSION@")
    unreleasedLink.set("https://github.com/zaproxy/community-scripts/compare/v@CURRENT_VERSION@...HEAD")

    manifest {
        author.set("ZAP Community")
        url.set("https://github.com/zaproxy/community-scripts")
        changesFile.set(tasks.named<ConvertMarkdownToHtml>("generateManifestChanges").flatMap { it.html })
        files.from(scriptsDir)
    }

    wikiGen {
        wikiFilesPrefix.set("HelpAddons${zapAddOn.addOnId.get().capitalize()}")
        wikiDir.set(file("$rootDir/../zap-extensions-wiki/"))
    }
}

val jupiterVersion = "5.2.0"

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:$jupiterVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$jupiterVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$jupiterVersion")

    testImplementation("org.assertj:assertj-core:3.11.0")
    testImplementation("org.apache.commons:commons-lang3:3.8")

    // The following versions should match the ones of the add-ons.
    testImplementation("org.codehaus.groovy:groovy-all:2.4.14")
    testImplementation("org.jruby:jruby-complete:1.7.4")
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
        "extender",
        "httpfuzzerprocessor",
        "httpsender",
        "passive",
        "payloadgenerator",
        "payloadprocessor",
        "proxy",
        "sequence",
        "standalone",
        "targeted",
        "variant",
        "websocketfuzzerprocessor")

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

        googleJavaFormat().aosp()
    }
}

System.getenv("GITHUB_REF")?.let { ref ->
    if ("refs/tags/" !in ref) {
        return@let
    }

    tasks.register<CreateGitHubRelease>("createReleaseFromGitHubRef") {
        val targetTag = ref.removePrefix("refs/tags/")
        val targetAddOnVersion = targetTag.removePrefix("v")

        authToken.set(System.getenv("GITHUB_TOKEN"))
        repo.set(System.getenv("GITHUB_REPOSITORY"))
        tag.set(targetTag)

        title.set(provider { "Version ${zapAddOn.addOnVersion.get()}" })
        bodyFile.set(tasks.named<ExtractLatestChangesFromChangelog>("extractLatestChanges").flatMap { it.latestChanges })

        assets {
            register("add-on") {
                file.set(tasks.named<Jar>(AddOnPlugin.JAR_ZAP_ADD_ON_TASK_NAME).flatMap { it.archiveFile })
            }
        }

        doFirst {
            val addOnVersion = zapAddOn.addOnVersion.get()
            require(addOnVersion == targetAddOnVersion) {
                "Version of the tag $targetAddOnVersion does not match the version of the add-on $addOnVersion"
            }
        }
    }
}
