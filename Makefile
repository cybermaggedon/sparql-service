
CXXFLAGS += -I/usr/include/raptor2 -I/usr/include/rasqal -g
CXXFLAGS += -Iboost.http/include -Inetmindms -std=c++14

LIBS=-lpthread -lboost_system -lboost_coroutine -lrdf -lraptor2

all: sparql

OBJECTS=service.o netmindms/EdUrlParser.o rdf.o

sparql: ${OBJECTS}
	${CXX} ${CXXFLAGS} ${OBJECTS} -o $@ ${LIBS}

service.o: rdf.h

