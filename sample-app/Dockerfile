# syntax=docker/dockerfile:1
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q package -DskipTests

# Distroless: no shell, no package manager, small attack surface. Runs as non-root (uid 65532).
FROM gcr.io/distroless/java21-debian12:nonroot
COPY --from=build /src/target/app.jar /app/app.jar
EXPOSE 8080
USER nonroot
HEALTHCHECK NONE
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
