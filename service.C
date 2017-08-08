#include <iostream>
#include <algorithm>

#include <boost/utility/string_ref.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/http/buffered_socket.hpp>
#include <boost/http/algorithm.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <redland.h>

#include "rdf.h"
#include "EdUrlParser.h"

using namespace std;
using namespace boost;

#ifndef BASE_URI
#define BASE_URI "https://github.com/cybermaggedon/"
#endif

class sparql {
public:
    rdf::world* w;
    rdf::uri* base_uri;
    rdf::storage* s;
    rdf::model* m;
    sparql(const std::string& store, const std::string& name) {
	w = new rdf::world();
	s = new rdf::storage(*w, store, name);
	m = new rdf::model(*s);
	base_uri = new rdf::uri(*w, BASE_URI);
    }
    ~sparql() {
	delete base_uri;
	delete m;
	delete s;
	delete w;
    }
};

class http_reply_stream : public rdf::iostream {
private:
    boost::asio::yield_context& yield;
    boost::http::buffered_socket& socket;

public:
    http_reply_stream(raptor_world* rw, boost::http::buffered_socket& socket,
		      boost::asio::yield_context& yield) :
	yield(yield), socket(socket), iostream(rw) {
    }

    virtual int write(unsigned char* bytes, unsigned int len) {
	http::message reply;
	std::copy(bytes, bytes+len, std::back_inserter(reply.body()));
	socket.async_write(reply, yield);
	return 0;
    }
    
};

class connection: public std::enable_shared_from_this<connection>
{
private:
    sparql& s;
public:
    void operator()(asio::yield_context yield);

    asio::ip::tcp::socket &tcp_layer() {
	return socket.next_layer();
    }

    static std::shared_ptr<connection> make_connection(asio::io_service &ios,
                                                       int counter,
						       sparql& s) {
	return std::shared_ptr<connection>{new connection{ios, counter, s}};
    }

private:

    connection(asio::io_service &ios, int counter, sparql& s)
        : socket(ios)
        , counter(counter)
	, s(s) {}

    http::buffered_socket socket;
    int counter;

    std::string method;
    std::string path;
    http::message message;

};

void connection::operator()(asio::yield_context yield)
{

    auto self = shared_from_this();
    try {

	while (self->socket.is_open()) {

	    std::cerr << "r" << std::endl;

	    // Read request.
	    self->socket.async_read_request(self->method, self->path,
					    self->message, yield);
		
	    std::cerr << "s" << std::endl;


	    if (http::request_continue_required(self->message)) {
		// 100-CONTINUE
		self->socket.async_write_response_continue(yield);
	    }

	    std::cerr << "Q" << std::endl;

	    while (self->socket.read_state() != http::read_state::empty) {
		switch (self->socket.read_state()) {
		case http::read_state::message_ready:
		    // Read some body.
		    self->socket.async_read_some(self->message, yield);
		    break;
		case http::read_state::body_ready:
		    // Read trailers.
		    self->socket.async_read_trailers(self->message, yield);
		    break;
		default:;
		}
	    }

	    std::string payload;

	    std::cerr << "A" << std::endl;
	    
	    if (self->message.body().size() != 0) {
		std::copy(self->message.body().begin(),
			  self->message.body().end(),
			  std::back_inserter(payload));
	    } else {

		std::cerr << "B" << std::endl;
		EdUrlParser* url = EdUrlParser::parseUrl(self->path);
		payload = url->query;
		delete url;

	    }

	    std::cerr << "C" << std::endl;
		    
	    std::vector<query_kv_t> kvs;
	    int num = EdUrlParser::parseKeyValueList(&kvs, payload);

	    std::string query;
	    std::string output;
	    std::string callback;

	    for(int i = 0; i < num; i++) {
		if (kvs[i].key == "query")
		    query = EdUrlParser::urlDecode(kvs[i].val);
		if (kvs[i].key == "output")
		    output = EdUrlParser::urlDecode(kvs[i].val);
		if (kvs[i].key == "callback")
		    callback = EdUrlParser::urlDecode(kvs[i].val);
	    }

	    std::cout << "Query: " << query << std::endl;
	    std::cout << std::endl;

	    /* Create new query */
	    rdf::query qry(*(s.w), query, *(s.base_uri));

	    std::cout << "Query executed." << std::endl;
	    
	    /* Execute query */
	    rdf::results& res = qry.execute(*(s.m));

	    std::cout << "Results acquired." << std::endl;
	
	    enum { IS_GRAPH, IS_BINDINGS, IS_BOOLEAN } results_type;

	    if (res.is_graph())
		results_type = IS_GRAPH;
	    else if (res.is_bindings())
		results_type = IS_BINDINGS;
	    if (res.is_boolean())
		results_type = IS_BOOLEAN;

	    if (output == "json") {

		http::message reply;
		
		std::pair<std::string,std::string>
		    ct("Content-type",
		       "application/sparql-results+json");

		std::pair<std::string,std::string>
		    acao("Access-Control-Allow-Origin", "*");

		// FIXME: Hide this in iostream.
		raptor_world* rw = raptor_new_world();
		
		reply.headers().insert(ct);
		reply.headers().insert(acao);

		rdf::formatter f(res, "json", "");

		self->socket.async_write_response_metadata(200,
							   string_ref("OK"),
							   reply,
							   yield);

		if (callback != "") {
		    reply.body().clear();
		    std::copy(callback.begin(), callback.end(),
			      std::back_inserter(reply.body()));
		    reply.body().push_back('(');
		    socket.async_write(reply, yield);
		}

		http_reply_stream strm(rw, self->socket, yield);

		f.write(strm, res);

		if (callback != "") {
		    reply.body().clear();
		    reply.body().push_back(')');
		    socket.async_write(reply, yield);
		}

		self->socket.async_write_end_of_message( yield);

	    } else if (results_type == IS_GRAPH) {

		rdf::stream& ntr_strm = res.as_stream();

		http::message reply;
		
		std::pair<std::string,std::string>
		    ct("Content-type",
		       "application/sparql-results+xml");

		std::pair<std::string,std::string>
		    acao("Access-Control-Allow-Origin", "*");

		// FIXME: Hide this in iostream.
		// FIXME: raptor_world is leaked.
		raptor_world* rw = raptor_new_world();

		std::string mime_type = "application/sparql-results+xml";
		
		reply.headers().insert(ct);
		reply.headers().insert(acao);

		rdf::serializer serl(*(s.w), "rdfxml");

		self->socket.async_write_response_metadata(200,
							   string_ref("OK"),
							   reply,
							   yield);

		http_reply_stream strm(rw, self->socket, yield);

		serl.write_stream_to_iostream(ntr_strm, strm);
		
		self->socket.async_write_end_of_message(yield);
		    
	    } else {

		http::message reply;
		
		std::pair<std::string,std::string>
		    ct("Content-type",
		       "application/sparql-results+xml");

		std::pair<std::string,std::string>
		    acao("Access-Control-Allow-Origin", "*");

		// FIXME: Hide this in iostream.
		raptor_world* rw = raptor_new_world();

		std::string mime_type = "application/sparql-results+xml";
		
		reply.headers().insert(ct);
		reply.headers().insert(acao);

		rdf::formatter f(res, "", mime_type);

		self->socket.async_write_response_metadata(200,
							   string_ref("OK"),
							   reply,
							   yield);

		http_reply_stream strm(rw, self->socket, yield);

		f.write(strm, res);

		self->socket.async_write_end_of_message( yield);

	    }

		    
	    return;

	}

    } catch (std::exception &e) {
	std::cerr << "Exception: " << e.what() << std::endl;;
	return;
    }
}



int main(int argc, char** argv)
{

    if (argc != 4) {
	std::cerr << "Usage:" << std::endl
		  << "\tsparql <port> <store> <storename>" << std::endl;
	exit(1);
    }

    std::istringstream istr(argv[1]);
    unsigned int port;
    istr >> port;

    const std::string store(argv[2]);
    const std::string name(argv[3]);

    sparql s(store, name);

    asio::io_service ios;
    asio::ip::tcp::acceptor acceptor(ios,
                                     asio::ip::tcp
                                     ::endpoint(asio::ip::tcp::v6(), port));

    auto signal_handler = [&s](const boost::system::error_code& error,
			       int signal)
	{
	    std::cout << "Stopping..." << std::endl;
	    // FIXME: Need to stop anything?
	    std::cout << "Stopped." << std::endl;
	    exit(1);
	};

    boost::asio::signal_set signals(ios, SIGINT, SIGTERM);

    signals.async_wait(signal_handler);

    auto work = [&acceptor, &s](asio::yield_context yield) {
        int counter = 0;
        for ( ; true ; ++counter ) {
            try {
                auto connection
                    = connection::make_connection(acceptor.get_io_service(),
                                                  counter, s);
                acceptor.async_accept(connection->tcp_layer(), yield);

                auto handle_connection
                    = [connection](asio::yield_context yield) mutable {
                    (*connection)(yield);
                };
                spawn(acceptor.get_io_service(), handle_connection);
            } catch (std::exception &e) {
                cerr << "Accept exception: " << e.what() << endl;
            }
        }
    };

    spawn(ios, work);
    ios.run();

    return 0;

}

