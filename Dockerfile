FROM maven:3.8.6-eclipse-temurin-17
COPY ./target/mm-authorization-service-*.jar /home/as/mm-authorization-service.jar
CMD ["java", "-jar", "/home/as/mm-authorization-service.jar"]
