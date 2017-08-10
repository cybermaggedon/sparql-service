
// This is the buffer size for the received HTTP message.
#define BOOST_HTTP_SOCKET_DEFAULT_BUFFER_SIZE 16384

#include <iostream>
#include <algorithm>

#include <boost/asio/spawn.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/http/buffered_socket.hpp>
#include <boost/http/algorithm/query.hpp>
#include <boost/http/request.hpp>
#include <boost/http/response.hpp>
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

// SPARQL state, handles to the store etc.
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

// Used to connect a Redland thing which outputs on an iostream to the HTTP
// socket so that data is streamed back as an HTTP response.
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
	http::response reply;
	std::copy(bytes, bytes+len, std::back_inserter(reply.body()));
	socket.async_write(reply, yield);
	return 0;
    }
    
};

// An HTTP connection
class connection: public std::enable_shared_from_this<connection>
{
private:
    sparql& s;
public:

    // This is the handler for a connection
    void operator()(asio::yield_context yield);

    // Returns the TCP layer socket.
    asio::ip::tcp::socket &tcp_layer() {
	return socket.next_layer();
    }

    // Creates a new object when an HTTP connection is received.
    static std::shared_ptr<connection> make_connection(asio::io_service &ios,
						       sparql& s) {
	return std::shared_ptr<connection>{new connection{ios, s}};
    }

private:

    // Constructor.
    connection(asio::io_service &ios, sparql& s)
        : socket(ios)
	, s(s) {}

    // The HTTP socket.
    http::buffered_socket socket;

    // Incoming HTTP request.
    http::request request;

};

// HTTP connection body
void connection::operator()(asio::yield_context yield)
{

    auto self = shared_from_this();
    try {

	// Keep going while socket is open.
	while (self->socket.is_open()) {

	    // Read request.
	    self->socket.async_read_request(self->request, yield);

	    // Handle 100-CONTINUE case.
	    if (http::request_continue_required(self->request)) {
		// 100-CONTINUE
		self->socket.async_write_response_continue(yield);
	    }

	    // Receive HTTP header.
	    while (self->socket.read_state() != http::read_state::empty) {
		switch (self->socket.read_state()) {
		case http::read_state::message_ready:
		    // Read some body.
		    self->request.body().clear(); // free unused resources
		    self->socket.async_read_some(self->request, yield);
		    break;
		case http::read_state::body_ready:
		    // Read trailers.
		    self->socket.async_read_trailers(self->request, yield);
		    break;
		default:;
		}
	    }

	    // If there's body, use it for parameters, otherwise, the
	    // parameters are in the URL.
	    std::string payload;
	    if (self->request.body().size() != 0) {
		std::copy(self->request.body().begin(),
			  self->request.body().end(),
			  std::back_inserter(payload));
	    } else {
		EdUrlParser* url =
		    EdUrlParser::parseUrl(self->request.target());
		payload = url->query;
		delete url;
	    }

	    // Parse parameters for key/value pairs.
	    std::vector<query_kv_t> kvs;
	    int num = EdUrlParser::parseKeyValueList(&kvs, payload);

	    // Collect query, output and callback parameters by URL-decoding.
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

	    std::cout << std::endl;
	    std::cout << "Query: " << query << std::endl;

	    enum { IS_GRAPH, IS_BINDINGS, IS_BOOLEAN } results_type;

	    std::shared_ptr<rdf::query> qry;
	    std::shared_ptr<rdf::results> res;

	    try {

		/* Create new query */
		qry = std::make_shared<rdf::query>(rdf::query(*(s.w), query, *(s.base_uri)));
		std::cout << "Query executed." << std::endl;
	    
		/* Execute query */
		res = qry->execute(*(s.m));

		std::cout << "Results acquired." << std::endl;

	    } catch (std::exception& e) {

		// If there's an exception, that's a 500 error.
		http::response reply;

		// Status code and response.
		reply.status_code() = 500;
		reply.reason_phrase() = "Internal Server Error";

		// Add text/plain content type
		std::pair<std::string,std::string>
		    ct("Content-type", "text/plain");
		reply.headers().insert(ct);

		// Write start of response.
		self->socket.async_write_response_metadata(reply, yield);

		// Payload is the exception text.
		reply.body().clear();
		std::string err = e.what();
		std::copy(err.begin(), err.end(),
			  std::back_inserter(reply.body()));

		// Write exception text.
		socket.async_write(reply, yield);

		// End of response.
		self->socket.async_write_end_of_message( yield);

		return;

	    }

	    // Work out results type.
	    if (res->is_graph())
		results_type = IS_GRAPH;
	    else if (res->is_bindings())
		results_type = IS_BINDINGS;
	    if (res->is_boolean())
		results_type = IS_BOOLEAN;

	    // If output is JSON...
	    if (output == "json") {

		// Reply to be constructed.
		http::response reply;

		// Add SPARQL results JSON content type header.
		std::pair<std::string,std::string>
		    ct("Content-type",
		       "application/sparql-results+json");
		reply.headers().insert(ct);

		// Allows access from JavaScript outside of the domain.
		std::pair<std::string,std::string>
		    acao("Access-Control-Allow-Origin", "*");
		reply.headers().insert(acao);

		// FIXME: Hide this in iostream.
		raptor_world* rw = raptor_new_world();

		// Create a results formatter for JSON data.
		rdf::formatter f(*res, "json", "");

		// Response code 200 OK.
		reply.status_code() = 200;
		reply.reason_phrase() = "OK";

		// Start writing HTTP response.
		self->socket.async_write_response_metadata(reply, yield);

		// If using JSONP, return callback(X) instead of X.
		if (callback != "") {
		    reply.body().clear();
		    std::copy(callback.begin(), callback.end(),
			      std::back_inserter(reply.body()));
		    reply.body().push_back('(');
		    socket.async_write(reply, yield);
		}

		// Create an HTTP response streamer.
		http_reply_stream strm(rw, self->socket, yield);

		f.write(strm, *res);

		if (callback != "") {
		    reply.body().clear();
		    reply.body().push_back(')');
		    socket.async_write(reply, yield);
		}

		// End of response.
		self->socket.async_write_end_of_message( yield);

	    } else if (results_type == IS_GRAPH) {
		
		std::shared_ptr<rdf::stream> ntr_strm = res->as_stream();
		
		http::response reply;
		
		// Add text/plain content type
		std::pair<std::string,std::string>
		    ct("Content-type",
		       "application/sparql-results+xml");
		
		// Allows access from JavaScript outside of the domain.
		std::pair<std::string,std::string>
		    acao("Access-Control-Allow-Origin", "*");
		
		// FIXME: Hide this in iostream.
		// FIXME: raptor_world is leaked.
		raptor_world* rw = raptor_new_world();
		
		std::string mime_type = "application/sparql-results+xml";
		
		reply.headers().insert(ct);
		reply.headers().insert(acao);
		
		rdf::serializer serl(*(s.w), "rdfxml");
		
		// Response code 200 OK.
		reply.status_code() = 200;
		reply.reason_phrase() = "OK";
		
		// Start writing HTTP response.
		self->socket.async_write_response_metadata(reply, yield);
		
		// Create an HTTP response streamer and write.
		http_reply_stream strm(rw, self->socket, yield);
		serl.write_stream_to_iostream(ntr_strm, strm);
		
		// End of response.
		self->socket.async_write_end_of_message(yield);
		
	    } else {
		
		http::response reply;
		
		// Add text/plain content type
		std::pair<std::string,std::string>
		    ct("Content-type",
		       "application/sparql-results+xml");

		// Allows access from JavaScript outside of the domain.
		std::pair<std::string,std::string>
		    acao("Access-Control-Allow-Origin", "*");

		// FIXME: Hide this in iostream.
		raptor_world* rw = raptor_new_world();

		std::string mime_type = "application/sparql-results+xml";
		
		reply.headers().insert(ct);
		reply.headers().insert(acao);

		rdf::formatter f(*res, "", mime_type);

		// Response code 200 OK.
		reply.status_code() = 200;
		reply.reason_phrase() = "OK";

		// Start writing HTTP response.
		self->socket.async_write_response_metadata(reply, yield);

		// Create an HTTP response streamer and write.
		http_reply_stream strm(rw, self->socket, yield);
		f.write(strm, *res);

		// End of response.
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
        for ( ; true ; ) {
            try {
                auto connection
                    = connection::make_connection(acceptor.get_io_service(),
                                                  s);
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

