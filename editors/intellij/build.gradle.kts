import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.intellij.platform.gradle.IntelliJPlatformType
import org.jetbrains.intellij.platform.gradle.models.ProductRelease

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.intellij.platform")
}

group = "app.factoryline"
version = "0.1.0"

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
        }
    }
    pluginVerification {
        ides {
            val requestedProduct = providers.gradleProperty("factorylineVerificationProduct").orNull
            if (requestedProduct == null) {
                current()
            } else {
                latest {
                    types.set(listOf(IntelliJPlatformType.valueOf(requestedProduct)))
                    channels.set(listOf(ProductRelease.Channel.RELEASE))
                    sinceBuild.set("252")
                    untilBuild.set("252.*")
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
