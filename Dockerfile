FROM openjdk:21
COPY ./build/libs/ApiGateway.jar ApiGateway.jar
ENTRYPOINT ["java", "-jar", "ApiGateway.jar"]