# Research-only toolchain. This obsolete base is not suitable for trusted production services.
FROM centos:6
RUN rm -f /etc/yum.repos.d/*.repo
COPY build/CentOS-Vault.repo /etc/yum.repos.d/CentOS-Vault.repo
RUN yum -y install rpm-build && yum clean all
