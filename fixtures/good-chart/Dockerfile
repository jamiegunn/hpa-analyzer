# syntax=docker/dockerfile:1
FROM eclipse-temurin:21.0.3_9-jdk AS build
WORKDIR /src
COPY . .
RUN ./mvnw -q -DskipTests package

FROM eclipse-temurin:21.0.3_9-jre
RUN groupadd -g 10001 app && useradd -u 10001 -g app -s /usr/sbin/nologin app \
    && mkdir /app && chown app:app /app
WORKDIR /app
COPY --from=build --chown=app:app /src/target/orders-service.jar app.jar
USER app
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=50 -XX:InitialRAMPercentage=50 \
    -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError \
    -XX:HeapDumpPath=/tmp -Xss1m"
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
