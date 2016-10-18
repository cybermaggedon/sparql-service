
CXXFLAGS += -I/usr/include/raptor2 -I/usr/include/rasqal -g
CXXFLAGS += -Ihttp/include -Inetmindms -std=c++11

LIBS=-lpthread -lboost_system -lboost_coroutine -lrdf -lraptor2

all: service

OBJECTS=service.o netmindms/EdUrlParser.o rdf.o

service: ${OBJECTS}
	${CXX} ${CXXFLAGS} ${OBJECTS} -o $@ ${LIBS}


service.o: rdf.h

#all: sparql

install:
	sudo cp sparql /usr/local/bin/
	sudo cp sparql.service /usr/lib/systemd/system/sparql.service
	sudo systemctl daemon-reload

sparql: sparql.o
	${CXX} ${CXXFLAGS} sparql.o -o sparql -lrdf -lmicrohttpd

