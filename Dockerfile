
FROM ubuntu:latest

RUN apt update && \
    apt upgrade -y && \
    apt install -y libboost-system1.74.0 libboost-coroutine1.74.0 && \
    apt install -y librasqal3 librdf0 libraptor2-0 librdf-storage-sqlite && \
    apt clean all

RUN mkdir /data/

COPY sparql /usr/local/bin/
RUN chmod 755 /usr/local/bin/sparql

WORKDIR /data/
CMD /usr/local/bin/sparql 8089 sqlite data.db
EXPOSE 8089

