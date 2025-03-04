FROM openjdk:21
COPY ./build/libs/gateway.jar gateway.jar
#ENTRYPOINT ["java", "-Dspring.profiles.active=dev", "-jar", "gateway.jar"]
ENTRYPOINT ["java", "-Dspring.profiles.active=prod", "-jar", "gateway.jar"]