FROM eclipse-temurin:17.0.10_7-jre-jammy
WORKDIR /app
COPY target/payments.jar /app/payments.jar
USER 10001
EXPOSE 8080
ENTRYPOINT ["java", "-XX:+UseG1GC", "-jar", "/app/payments.jar"]
