plugins {
    `java-library`
    id("io.spring.dependency-management")
}

repositories {
    mavenCentral()
}
dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:4.0.5")
    }
}

dependencies {

    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.boot:spring-boot-starter-web")
    api("com.fasterxml.jackson.core:jackson-databind")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")

    api("io.jsonwebtoken:jjwt-api:0.13.0")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.13.0")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.13.0")

    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
