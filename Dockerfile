
# FROM ubuntu:latest
FROM fedora:36

# RUN apt update && \
#     apt upgrade -y && \
#     apt install -y libboost-system1.71.0 libboost-coroutine1.71.0 && \
#     apt install -y librasqal3 librdf0 libraptor2-0 librdf-storage-sqlite && \
#     apt clean all

RUN dnf upgrade -y && \
    dnf install -y rasqal-devel redland-devel raptor2-devel && \
    dnf install -y boost-system boost-coroutine && \
    dnf clean all

RUN mkdir /data/

COPY sparql /usr/local/bin/
RUN chmod 755 /usr/local/bin/sparql

WORKDIR /data/
CMD /usr/local/bin/sparql 8089 sqlite data.db
EXPOSE 8089

