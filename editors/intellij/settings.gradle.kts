import org.jetbrains.intellij.platform.gradle.extensions.intellijPlatform
import org.gradle.api.JavaVersion

val requiredBuildJava = JavaVersion.VERSION_21
check(JavaVersion.current() == requiredBuildJava) {
    "FactoryLine IntelliJ release builds require JDK 21 exactly; " +
        "detected Java ${JavaVersion.current()}. Set JAVA_HOME to a JDK 21 installation before running Gradle."
}

rootProject.name = "factoryline-intellij"

pluginManagement {
    plugins {
        id("org.jetbrains.kotlin.jvm") version "2.4.10"
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
    id("org.jetbrains.intellij.platform.settings") version "2.18.1"
}

@Suppress("UnstableApiUsage")
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        intellijPlatform {
            defaultRepositories()
        }
    }
}
