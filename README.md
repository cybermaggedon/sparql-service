
# `sparql-service`

## Introduction

This is a SPARQL 1.0 endpoint i.e. network service which executes SPARQL queries
on behalf of a client.  The queries are executed against a data set held on
the server side.  The SPARQL service is read-only and does not support
update commands.

This is based on the Redland RDF libraries and uses Redland to implement
SPARQL queries.

sparql-service can use any of the backend stores supported by Redland.
You can use the Redland command-line utilities to build the stores from
any format supported by Redland.

`sparql-service` is written in C++ and has an embedded web server
based on Boost ASIO.  It handles multiple concurrent queries and streaming
of data.

The service does not build the entire result set in memory before sending,
building the result set incrementally, so there is no performance impact
in executing a query which could result a large data set only to
close the connection part-way through.

## Build

On Ubuntu dependencies are:
- libboost-system-dev
- libboost-coroutine-dev
- libboost-dev
- librasqal3-dev
- librdf-dev
- libraptor2-dev
- g++
- make

Just run `make`.

## Usage

```
  sparql <portnum> <store-type> <store-name>
```

Where:
- `portnum` is the port number to listen for SPARQL queries on.
- `store-type` is a kind of RDF store e.g. `sqlite`
- `store-name` is the store instance e.g. for `sqlite` it's the Sqlite3
  database pathname.

## Getting started

A sample RDF dataset is included in partygate.ttl, which is in Turtle format.

This can be converted to a Redland data store in Sqlite format using this
command:

```
rdfproc -n -s sqlite partygate.db parse partygate.ttl turtle
```

The resultant `partygate.db` file is a Redland RDF store in a
Sqlite database.

The resulting dataset can then be served as a SPARQL dataset e.g.

```
  sparql 8089 sqlite partygate.db
```

## Docker container

Container name is:
```
docker.io/cybermaggedon/sparql-service
```

Expects to find the store as sqlite format store at /data/data.db, so
you can mount a volume on `/data`.

The container exposes the SPARQL service via HTTP on port 8089.  The container
does not support TLS, if you want to use TLS add a front-end proxy using e.g.
nginx.

You can override the default container command line to change the
store filename or use other store types.  The container default command is:
```
sparql 8089 sqlite data.db
```

