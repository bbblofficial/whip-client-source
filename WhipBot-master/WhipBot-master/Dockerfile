FROM eclipse-temurin:21-jdk AS build

WORKDIR /app

ARG USERNAME
ARG TOKEN

COPY gradle gradle
COPY gradlew build.gradle settings.gradle ./
RUN chmod +x gradlew && ./gradlew dependencies --no-daemon

COPY src src
RUN ./gradlew shadowJar --no-daemon

FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=build /app/build/libs/WhipBot.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]