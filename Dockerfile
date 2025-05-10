FROM openjdk:21
COPY ./build/libs/gateway.jar gateway.jar

# 기본값 설정
ENV SPRING_PROFILE=prod
ENV TZ=Asia/Seoul

# 실행 시점에 SPRING_PROFILE 값을 외부에서 받아 사용
ENTRYPOINT ["sh", "-c", "java -Dspring.profiles.active=${SPRING_PROFILE} -Duser.timezone=${TZ} -jar gateway.jar"]
