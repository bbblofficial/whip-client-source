FROM eclipse-temurin:21-jre

WORKDIR /app

COPY build/libs/*.jar app.jar

RUN mkdir -p /app/certs

EXPOSE 7777

ENTRYPOINT ["java", "-jar", "app.jar"]
