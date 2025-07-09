# Dockerfile.ubuntu.22.04
FROM ubuntu:22.04
ARG VERSION=latest
WORKDIR /root
RUN apt-get update ; apt install -y openjdk-21-jre-headless
COPY ./target/gallery-0.0.1-SNAPSHOT.jar gallery-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java","-jar","gallery-0.0.1-SNAPSHOT.jar"]
