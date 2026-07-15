import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.intellij.platform.gradle.IntelliJPlatformType
import org.jetbrains.intellij.platform.gradle.models.ProductRelease
import java.nio.charset.StandardCharsets
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.intellij.platform")
}

group = "app.factoryline"
version = "0.1.2"

kotlin {
    jvmToolchain(21)
}

dependencies {
    testImplementation(kotlin("test"))

    intellijPlatform {
        intellijIdea("2025.2.6.2")
        testFramework(TestFrameworkType.Platform)
    }
}

intellijPlatform {
    buildSearchableOptions = false
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "252"
            // This adapter uses only platform APIs. Do not fabricate an upper
            // limit from the build IDE; binary verification covers current IDEs.
            untilBuild = provider { null }
        }
    }
    publishing {
        channels.set(
            providers.gradleProperty("factorylineMarketplaceChannel")
                .map { listOf(it) }
                .orElse(listOf("default"))
        )
    }
    pluginVerification {
        ides {
            val requestedProduct = providers.gradleProperty("factorylineVerificationProduct").orNull
            val localVerificationIde = providers.gradleProperty("factorylineLocalVerificationIde").orNull
            if (localVerificationIde != null) {
                local(file(localVerificationIde))
            } else if (requestedProduct == null) {
                current()
            } else {
                latest {
                    types.set(listOf(IntelliJPlatformType.valueOf(requestedProduct)))
                    channels.set(listOf(ProductRelease.Channel.RELEASE))
                    sinceBuild.set("252")
                }
            }
        }
    }
}

// The adapter's tests are pure parsing and filesystem checks. They do not load
// the IntelliJ runtime, so only the production plugin classes need instrumentation.
tasks.named("instrumentTestCode") {
    enabled = false
}

tasks.register("marketplacePreflight") {
    group = "verification"
    description = "Fails if the packaged plugin misses Marketplace-required listing metadata."
    dependsOn(tasks.named("buildPlugin"))
    inputs.file(layout.buildDirectory.file("distributions/factoryline-intellij-$version.zip"))

    doLast {
        val archive = inputs.files.singleFile
        check(archive.isFile) { "Expected the plugin ZIP at $archive." }

        val requiredEntries = setOf(
            "META-INF/plugin.xml",
            "META-INF/pluginIcon.svg",
            "META-INF/pluginIcon_dark.svg"
        )
        val packagedEntries = linkedMapOf<String, ByteArray>()
        ZipFile(archive).use { distribution ->
            val pluginJar = distribution.entries().asSequence().firstOrNull { entry ->
                entry.name.startsWith("factoryline-intellij/lib/") && entry.name.endsWith(".jar")
            } ?: error("The plugin distribution does not contain its main JAR.")

            ZipInputStream(distribution.getInputStream(pluginJar)).use { plugin ->
                while (true) {
                    val entry = plugin.nextEntry ?: break
                    if (entry.name in requiredEntries) {
                        packagedEntries[entry.name] = plugin.readBytes()
                    }
                }
            }
        }

        val missing = requiredEntries - packagedEntries.keys
        check(missing.isEmpty()) { "Plugin package is missing Marketplace entries: ${missing.sorted().joinToString()}." }

        val pluginXml = packagedEntries.getValue("META-INF/plugin.xml").toString(StandardCharsets.UTF_8)
        check(pluginXml.contains("<idea-plugin url=\"https://github.com/zrk222/code-factory\"")) {
            "plugin.xml must expose the public project URL."
        }
        check(pluginXml.contains("<vendor email=\"rkatz22@gmail.com\" url=\"https://github.com/zrk222/code-factory\"")) {
            "plugin.xml must expose a reachable vendor URL and email."
        }
        check(pluginXml.contains("<change-notes>")) { "plugin.xml must include release notes." }
    }
}
