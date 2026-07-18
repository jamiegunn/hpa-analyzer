FROM openjdk:8u151-jdk

ENV JAVA_OPTS="-Xmx3g -Xms512m -XX:MaxPermSize=256m -Dspring.profiles.active=prod"
ENV DB_PASSWORD=changeme123

ADD https://internal.example.com/tools/agent.jar /opt/agent.jar

COPY target/payments.jar /app/payments.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/payments.jar"]
