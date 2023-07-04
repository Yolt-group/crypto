FROM 627987680837.dkr.ecr.eu-central-1.amazonaws.com/prd/yolt-openjdk-17-centos:693517
USER root

ARG VAULT_VERSION=1.7.1

# install assorted tools
RUN yum update -y
RUN yum install -y wget jq unzip less

# install jq
RUN yum install -y epel-release
RUN yum install -y jq

# install cloud hsm jce
RUN wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-jce-latest.el7.x86_64.rpm
RUN yum -y install ./cloudhsm-jce-latest.el7.x86_64.rpm

# install aws cli
RUN wget -q https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip
RUN unzip awscli-exe-linux-x86_64.zip
RUN ./aws/install
RUN aws --version

# Security patching
RUN yum -y update && yum -y clean all
# Cleanup.
RUN yum remove -y unzip && yum clean all

USER yolt

# The jar was exploded in the gitlab pipeline. This gives us more speed due to re-usage of the dependencies in the
# lib directory. They are cached locally on the gitlab runner (which uses a volume on the k8s worker).
COPY BOOT-INF/lib /app/lib
COPY META-INF /app/META-INF
COPY BOOT-INF/classes /app

# The awk (search) + tr (remove newline) trick here gets the main class from the MANIFEST.MF file, since we need it to run the application.
ENTRYPOINT ["sh", "-c", "java -XX:+UnlockExperimentalVMOptions -XX:MaxRAMPercentage=75.0 -XX:-OmitStackTraceInFastThrow ${JAVA_OPTS} -Djava.security.egd=file:/dev/./urandom -cp app:app/lib/* `cat /app/META-INF/MANIFEST.MF | awk '/Start-Class/ {print $2}' | tr '\r' ' '`"]
