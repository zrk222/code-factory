import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.intellij.platform.gradle.IntelliJPlatformType
import org.jetbrains.intellij.platform.gradle.models.ProductRelease
import org.jetbrains.intellij.platform.gradle.tasks.PublishPluginTask
import org.jetbrains.intellij.platform.gradle.tasks.VerifyPluginTask
import org.jetbrains.kotlin.gradle.dsl.JvmDefaultMode
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Copy
import java.nio.charset.StandardCharsets
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

abstract class MarketplacePreflightTask : DefaultTask() {
    @get:InputFile
    abstract val archive: RegularFileProperty

    @get:Input
    abstract val pluginVersion: Property<String>

    @TaskAction
    fun inspectArchive() {
        val archiveFile = archive.get().asFile
        check(archiveFile.isFile) { "Expected the plugin ZIP at $archiveFile." }
        check(archiveFile.length() <= 400L * 1024L * 1024L) {
            "Plugin archive is ${archiveFile.length()} bytes; Marketplace uploads are limited to 400 MiB."
        }

        val requiredEntries = setOf(
            "META-INF/plugin.xml",
            "META-INF/pluginIcon.svg",
            "META-INF/pluginIcon_dark.svg",
            "META-INF/licenses/LICENSE-MIT.txt",
            "META-INF/licenses/LICENSE-APACHE.txt",
            "META-INF/licenses/NOTICE.txt",
        )
        val packagedEntries = linkedMapOf<String, ByteArray>()
        val packagedJarEntries = linkedSetOf<String>()
        ZipFile(archiveFile).use { distribution ->
            check(distribution.entries().asSequence().all { entry ->
                entry.name.startsWith("factoryline-intellij/") && !entry.name.contains("..")
            }) { "Plugin distribution contains an unsafe or unexpected top-level path." }
            val pluginJar = distribution.entries().asSequence().firstOrNull { entry ->
                entry.name.startsWith("factoryline-intellij/lib/") && entry.name.endsWith(".jar")
            } ?: error("The plugin distribution does not contain its main JAR.")

            ZipInputStream(distribution.getInputStream(pluginJar)).use { plugin ->
                while (true) {
                    val entry = plugin.nextEntry ?: break
                    packagedJarEntries += entry.name
                    if (entry.name in requiredEntries) {
                        packagedEntries[entry.name] = plugin.readBytes()
                    }
                }
            }
        }

        val missing = requiredEntries - packagedEntries.keys
        check(missing.isEmpty()) { "Plugin package is missing Marketplace entries: ${missing.sorted().joinToString()}." }

        for (iconPath in listOf("META-INF/pluginIcon.svg", "META-INF/pluginIcon_dark.svg")) {
            val icon = packagedEntries.getValue(iconPath).toString(StandardCharsets.UTF_8)
            check(icon.contains("<svg") && icon.contains("width=\"40\"") && icon.contains("height=\"40\"")) {
                "$iconPath must remain a 40 by 40 SVG in the generated plugin package."
            }
        }

        val pluginXml = packagedEntries.getValue("META-INF/plugin.xml").toString(StandardCharsets.UTF_8)
        check(pluginXml.contains("<idea-plugin url=\"https://github.com/zrk222/code-factory\"")) {
            "plugin.xml must expose the public project URL."
        }
        check(pluginXml.contains("<vendor email=\"rkatz22@gmail.com\" url=\"https://github.com/zrk222/code-factory\"")) {
            "plugin.xml must expose a reachable vendor URL and email."
        }
        val requiredDescriptorFragments = setOf(
            "<id>app.factoryline</id>",
            "<name>FactoryLine AI Proof</name>",
            "<version>${pluginVersion.get()}</version>",
            "<idea-version since-build=\"252\"",
            "<depends>com.intellij.modules.platform</depends>",
            "<depends>com.intellij.modules.vcs</depends>",
            "id=\"app.factoryline.intellij.openGuardian\"",
            "class=\"app.factoryline.intellij.OpenGuardianAction\"",
            "Your IDE feels slow. Your AI code looks fine.",
            "Add Guardian Core as the first tool-window tab",
        )
        val missingDescriptorFragments = requiredDescriptorFragments.filterNot(pluginXml::contains)
        check(missingDescriptorFragments.isEmpty()) {
            "Patched plugin.xml is missing required Marketplace or Guardian metadata: ${missingDescriptorFragments.joinToString()}."
        }
        check(!pluginXml.contains("until-build=")) {
            "The packaged descriptor must retain open-ended compatibility; do not introduce an unverified upper build bound."
        }
        check(!pluginXml.contains("$5.95") && !pluginXml.contains("optional Freemium entitlement")) {
            "The free Marketplace descriptor must not advertise inactive paid pricing or entitlements."
        }
        check(!pluginXml.contains("star Code Factory", ignoreCase = true)) {
            "Marketplace metadata must not include an in-product promotion request."
        }
        check(pluginXml.contains("<change-notes>")) { "plugin.xml must include release notes." }

        val prohibitedArtifactEntries = listOf(".env", ".git/", "id_rsa", "credentials", "secrets")
        val prohibited = packagedJarEntries.filter { entry ->
            prohibitedArtifactEntries.any { marker -> entry.contains(marker, ignoreCase = true) }
        }
        check(prohibited.isEmpty()) {
            "Plugin JAR contains prohibited source-control, credential, or secret-shaped entries: ${prohibited.joinToString()}."
        }
    }
}

abstract class GuardianReleaseGateTask : DefaultTask() {
    @get:InputDirectory
    abstract val verifierReports: DirectoryProperty

    @TaskAction
    fun requireCompatibleVerdict() {
        val verdicts = verifierReports.get().asFile.walkTopDown()
            .filter { it.name == "verification-verdict.txt" }
            .toList()
        check(verdicts.any { it.readText().trim() == "Compatible" }) {
            "Guardian release gate requires at least one compatible Plugin Verifier verdict."
        }
    }
}

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.intellij.platform")
}

group = "app.factoryline"
version = "0.8.22"

// Keep release task inputs configuration-cache safe. Do not resolve the
// Project from a task action: Gradle 9.5 treats that as a release-gate error.
val factoryLineVersion = version.toString()
val marketplaceArchive = layout.buildDirectory.file("distributions/factoryline-intellij-$factoryLineVersion.zip")
val pluginVerifierReports = layout.buildDirectory.dir("reports/pluginVerifier")

kotlin {
    jvmToolchain(21)
    compilerOptions {
        // Kotlin 2.2+ defaults to compatibility bridges for interface defaults.
        // Those bridges make this Java-platform ToolWindowFactory appear to
        // override IntelliJ internal/deprecated methods. The plugin exposes no
        // Kotlin interfaces as public API, so direct JVM defaults are safe.
        jvmDefault.set(JvmDefaultMode.NO_COMPATIBILITY)
    }
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

// Ship the repository's existing dual-license terms and notice inside the
// distributable so the local artifact carries the same legal context as its
// Marketplace/source listing. Vendor-console EULA and trader declarations
// remain Marketplace-owner responsibilities.
tasks.named<Copy>("processResources") {
    from(project.file("../../LICENSE-MIT")) {
        into("META-INF/licenses")
        rename { "LICENSE-MIT.txt" }
    }
    from(project.file("../../LICENSE-APACHE")) {
        into("META-INF/licenses")
        rename { "LICENSE-APACHE.txt" }
    }
    from(project.file("../../NOTICE")) {
        into("META-INF/licenses")
        rename { "NOTICE.txt" }
    }
}

// Compatibility jobs verify the immutable ZIP already built and checked by the
// upstream CI job. Local invocations retain the plugin task's normal output.
tasks.named<VerifyPluginTask>("verifyPlugin") {
    providers.gradleProperty("factorylineVerificationArchive").orNull?.let { archive ->
        archiveFile.set(file(archive))
    }
}

tasks.register<MarketplacePreflightTask>("marketplacePreflight") {
    group = "verification"
    description = "Fails if the packaged plugin misses Marketplace-required metadata, Guardian action, or safe archive boundaries."
    dependsOn(tasks.named("buildPlugin"))
    archive.set(marketplaceArchive)
    pluginVersion.set(factoryLineVersion)
}

/**
 * Repeatable local release gate for Guardian Core and existing plugin behavior.
 * The full product matrix is enforced separately in CI before Marketplace publish.
 */
tasks.register<GuardianReleaseGateTask>("guardianReleaseGate") {
    group = "verification"
    description = "Runs Guardian Core behavior tests, package metadata checks, and current-platform Plugin Verifier validation."
    dependsOn(
        tasks.named("test"),
        tasks.named("buildPlugin"),
        tasks.named("verifyPlugin"),
        tasks.named("marketplacePreflight"),
    )

    verifierReports.set(pluginVerifierReports)
}

// CI validates the Marketplace ZIP in an unprivileged job, uploads it as an
// immutable Actions artifact, and passes that exact file to the privileged
// publishing job. Local publishing keeps the plugin task's normal build output.
tasks.named<PublishPluginTask>("publishPlugin") {
    providers.gradleProperty("factorylineMarketplaceArchive").orNull?.let { archive ->
        archiveFile.set(file(archive))
    }
}
