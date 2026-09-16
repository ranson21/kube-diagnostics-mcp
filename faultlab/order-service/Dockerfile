# syntax=docker/dockerfile:1
# Multi-stage: Maven build (no tests) -> slim JRE runtime.
FROM maven:3-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN --mount=type=cache,target=/root/.m2,sharing=locked mvn -B --no-transfer-progress -DskipTests dependency:go-offline
COPY src ./src
RUN --mount=type=cache,target=/root/.m2,sharing=locked mvn -B --no-transfer-progress -DskipTests package

FROM eclipse-temurin:21-jre
# NOTE: JAVA_TOOL_OPTIONS is intentionally NOT set here; the k8s manifests inject it
# (that is where the heap/limit-mismatch fault lives).
WORKDIR /app
COPY --from=build /build/target/app.jar /app/app.jar
# FAULT (security/runs-as-root): no USER directive, and the Deployment sets no securityContext,
# so the JVM runs as uid 0. Fix: add 'RUN useradd -r -u 10001 app' + 'USER 10001' here and/or
# securityContext.runAsNonRoot=true in the Deployment.
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
