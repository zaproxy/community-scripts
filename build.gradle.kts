plugins {
    `java-library`
    id("com.diffplug.gradle.spotless") version "3.15.0"
}

tasks {
    getByName<Wrapper>("wrapper") {
        gradleVersion = "4.10.2"
        distributionType = Wrapper.DistributionType.ALL
    }
}

repositories {
    mavenCentral()
}

val jupiterVersion = "5.2.0"

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter-api:$jupiterVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-params:$jupiterVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$jupiterVersion")

    testImplementation("org.assertj:assertj-core:3.11.0")
    testImplementation("org.apache.commons:commons-lang3:3.8")

    testRuntimeOnly("org.zaproxy:zap:2.7.0")

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

val scriptsDir = layout.buildDirectory.dir("scripts")
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
