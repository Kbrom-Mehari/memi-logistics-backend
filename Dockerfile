# Stage 1: Build the application
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /app

# Copy Gradle wrapper and build files
COPY gradlew .
COPY gradle gradle
COPY build.gradle.kts .
COPY settings.gradle.kts .

# Copy all source code
COPY src src
COPY auth-service auth-service
COPY shipment-service shipment-service
COPY common-security common-security

# Build the application
RUN ./gradlew bootJar --no-daemon

# Stage 2: Runtime image (smaller footprint)
FROM eclipse-temurin:21-jre
WORKDIR /app

# Copy the JAR from builder stage
COPY --from=builder /app/build/libs/memi-logistics-backend-*.jar app.jar

# Expose the port Spring Boot runs on
EXPOSE 8080

# Set environment variables (can be overridden at runtime)
ENV SPRING_PROFILES_ACTIVE=prod

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]