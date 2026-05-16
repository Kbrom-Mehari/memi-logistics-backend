plugins {
    java
    id("org.springframework.boot") version "4.0.5"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "com.memilogistics"
version = "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

subprojects {
    plugins.withId("java") {
        extensions.configure<org.gradle.api.plugins.JavaPluginExtension>("java") {
            toolchain {
                languageVersion = org.gradle.jvm.toolchain.JavaLanguageVersion.of(21)
            }
        }

        tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
            useJUnitPlatform()
        }
    }
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
    runtimeOnly("com.mysql:mysql-connector-j")
    runtimeOnly("org.postgresql:postgresql")
    implementation(project(":shipment-service"))
    implementation(project(":auth-service"))
    implementation(project(":common-security"))
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:3.0.2")
}
