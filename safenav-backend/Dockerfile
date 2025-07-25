# Stage 1: The "Builder" Stage
FROM maven:3.8.5-openjdk-17 AS builder

WORKDIR /app
COPY pom.xml .
COPY src ./src

# Run the Maven package command to build the .jar file. 

RUN mvn -f pom.xml clean package -DskipTests


# Stage 2: The "Production" Stage
FROM openjdk:17-jre-slim


WORKDIR /app

COPY --from=builder /app/target/safenav-backend-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
