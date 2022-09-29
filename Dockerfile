FROM maven:3.8.6-eclipse-temurin-17
RUN useradd --create-home --shell /bin/bash asuser
USER asuser
WORKDIR /home/as
ENV MAVEN_CONFIG=/home/as/.m2
COPY ./target/money-management-authorization-service-*.jar /home/as/mm-authorization-service.jar
CMD ["java", "-jar", "/home/as/mm-authorization-service.jar"]
