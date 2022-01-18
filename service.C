
// This is the buffer size for the received HTTP message.
#define BOOST_HTTP_SOCKET_DEFAULT_BUFFER_SIZE 16384

#include <iostream>
#include <algorithm>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/buffer.hpp>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <redland.h>
#include <thread>

#include "rdf.h"
#include "EdUrlParser.h"

using namespace std;
using namespace boost;

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

#ifndef BASE_URI
#define BASE_URI "https://github.com/cybermaggedon/"
#endif

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

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
template<class Sender>
class http_reply_stream : public rdf::iostream {

private:
    Sender& sender;

public:
    http_reply_stream(raptor_world* rw, Sender& sender) :
	sender(sender), iostream(rw) {
    }

    virtual int write(unsigned char* bytes, unsigned int len) {
	auto buf = asio::const_buffer(static_cast<void *>(bytes), len);
	net::write(sender, http::make_chunk(buf));
	return 0;
    }
    
    virtual void write_end() {
	net::write(sender, http::make_chunk_last());
    }
    
};

//struct session;
//struct send_lambda;

/*
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

	    // Gets CORS Origin header
	    std::string origin;
	    auto iter = self->request.headers().find("origin");
	    if (iter != self->request.headers().end())
		origin = iter->second;

	    enum { IS_GRAPH, IS_BINDINGS, IS_BOOLEAN } results_type;

	    std::shared_ptr<rdf::query> qry;
	    std::shared_ptr<rdf::results> res;

	    try {

		// Create new query
		qry = std::make_shared<rdf::query>(rdf::query(*(s.w), query, *(s.base_uri)));
		std::cout << "Query executed." << std::endl;
	    
		// Execute query 
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

		// Allows access from JavaScript outside of the domain.
		if (origin != "") {
		    std::pair<std::string,std::string>
			acao("Access-Control-Allow-Origin", origin);
		    reply.headers().insert(acao);
		}

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
		if (origin != "") {
		    std::pair<std::string,std::string>
			acao("Access-Control-Allow-Origin", origin);
		    reply.headers().insert(acao);
		}

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

		// FIXME: Hide this in iostream.
		// FIXME: raptor_world is leaked.
		raptor_world* rw = raptor_new_world();
		
		std::string mime_type = "application/sparql-results+xml";
		
		// Allows access from JavaScript outside of the domain.
		if (origin != "") {
		    std::pair<std::string,std::string>
			acao("Access-Control-Allow-Origin", origin);
		    reply.headers().insert(acao);
		}

		reply.headers().insert(ct);
		
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

		// FIXME: Hide this in iostream.
		raptor_world* rw = raptor_new_world();

		std::string mime_type = "application/sparql-results+xml";
		
		reply.headers().insert(ct);

		// Allows access from JavaScript outside of the domain.
		if (origin != "") {
		    std::pair<std::string,std::string>
			acao("Access-Control-Allow-Origin", origin);
		    reply.headers().insert(acao);
		}

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
*/
//------------------------------------------------------------------------------

struct session;

    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit
        send_lambda(session& self)
            : self_(self)
        {
        }

        template<bool isRequest, class Body, class Fields>
        void
        operator()(http::message<isRequest, Body, Fields>&& msg) const;

    };

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
    class Body, class Allocator,
    class Send>
void
handle_request(
    sparql* s,
    http::request<Body, http::basic_fields<Allocator>>&& req,
    Send&& send)
{
    beast::error_code ec;

    // Returns a bad request response
    auto const bad_request =
    [&req](beast::string_view why)
    {
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };

    // Returns a not found response
    auto const not_found =
    [&req](beast::string_view target)
    {
        http::response<http::string_body> res{http::status::not_found, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "The resource '" + std::string(target) + "' was not found.";
        res.prepare_payload();
        return res;
    };

    // Returns a server error response
    auto const server_error =
    [&req](beast::string_view what)
    {
        http::response<http::string_body> res{http::status::internal_server_error, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "An error occurred: '" + std::string(what) + "'";
        res.prepare_payload();
        return res;
    };

    // Make sure we can handle the method
    if (req.method() != http::verb::post && req.method() != http::verb::get)
        return send(bad_request("Unknown HTTP-method"));

    // FIXME: Handle 100-expect

	    // If there's body, use it for parameters, otherwise, the
	    // parameters are in the URL.
	    std::string payload;
	    if (req.body().size() != 0) {
		std::copy(req.body().begin(),
			  req.body().end(),
			  std::back_inserter(payload));
	    } else {
		EdUrlParser* url =
		    EdUrlParser::parseUrl(std::string(req.target()));
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
	    
	    // Gets CORS Origin header
	    
	    std::string origin = std::string(req[http::field::access_control_allow_origin]);

	    enum { IS_GRAPH, IS_BINDINGS, IS_BOOLEAN } results_type;

	    std::shared_ptr<rdf::query> qry;
	    std::shared_ptr<rdf::results> results;

	    try {

		// Create new query
		qry = std::make_shared<rdf::query>(
		    rdf::query(*(s->w), query, *(s->base_uri))
		);
		std::cout << "Query executed." << std::endl;
	    
		// Execute query 
		results = qry->execute(*(s->m));

		std::cout << "Results acquired." << std::endl;

	    } catch (std::exception& e) {
		
		return send(bad_request(e.what()));
/* FIXME:
		// Allows access from JavaScript outside of the domain.
		if (origin != "") {
		    std::pair<std::string,std::string>
			acao("Access-Control-Allow-Origin", origin);
		    reply.headers().insert(acao);
		}
*/

	    }

	    // Work out results type.
	    if (results->is_graph())
		results_type = IS_GRAPH;
	    else if (results->is_bindings())
		results_type = IS_BINDINGS;
	    if (results->is_boolean())
		results_type = IS_BOOLEAN;

	    // If output is JSON...
	    if (output == "json") {

		http::response<http::empty_body> res{
		    http::status::ok,
		    11
		};
		
		res.set(http::field::server, "sparql-service 1.1");
		res.set(http::field::content_type,
			"application/sparql-results+json");
		res.keep_alive(req.keep_alive());

		res.chunked(true);

		// Allows access from JavaScript outside of the domain.
		if (origin != "")
		    res.set("Access-Control-Allow-Origin", origin);

		// FIXME: Hide this in iostream.
		// FIXME: rw is leaked.
		raptor_world* rw = raptor_new_world();

		// Create a results formatter for JSON data.
		// FIXME:
		rdf::formatter f(*results, "json", "");

		// Set up serialiser
		http::response_serializer<http::empty_body> sr{res};

		// Start writing HTTP response.
		http::write_header(send, sr);

		// If using JSONP, return callback(X) instead of X.
		if (callback != "") {
		    std::string part = callback + "(";
		    auto buf =
			asio::const_buffer(
			    static_cast<const void *>(part.c_str()),
			    part.size());
		    net::write(send, http::make_chunk(buf));
		}

		// Create an HTTP response streamer.
		http_reply_stream<send_lambda&> strm(rw, send);

		f.write(strm, *results);

		if (callback != "") {
		    std::string part = ")";
		    auto buf =
			asio::const_buffer(
			    static_cast<const void *>(part.c_str()),
			    part.size());
		    net::write(send, http::make_chunk(buf));
		}

		// End of response.

	    } else if (results_type == IS_GRAPH) {
		
		std::shared_ptr<rdf::stream> ntr_strm = results->as_stream();
		
		http::response<http::empty_body> res{
		    http::status::ok,
		    11
		};

		res.set(http::field::server, "sparql-service 1.1");
		res.set(http::field::content_type,
			"application/sparql-results+xml");
		res.keep_alive(req.keep_alive());

		res.chunked(true);

		// Allows access from JavaScript outside of the domain.
		if (origin != "")
		    res.set("Access-Control-Allow-Origin", origin);

		// FIXME: Hide this in iostream.
		// FIXME: rw is leaked.
		raptor_world* rw = raptor_new_world();
		
		rdf::serializer serl(*(s->w), "rdfxml");

		// Set up serialiser
		http::response_serializer<http::empty_body> sr{res};

		// Start writing HTTP response.
		http::write_header(send, sr);

		// Create an HTTP response streamer and write.
		http_reply_stream<send_lambda&> strm(rw, send);

		serl.write_stream_to_iostream(ntr_strm, strm);
		
	    } else {
		
		std::shared_ptr<rdf::stream> ntr_strm = results->as_stream();
		
		http::response<http::empty_body> res{
		    http::status::ok,
		    11
		};

		res.set(http::field::server, "sparql-service 1.1");
		res.set(http::field::content_type,
			"application/sparql-results+xml");
		res.keep_alive(req.keep_alive());

		res.chunked(true);

		// Allows access from JavaScript outside of the domain.
		if (origin != "")
		    res.set("Access-Control-Allow-Origin", origin);

		// FIXME: Hide this in iostream.
		// FIXME: rw is leaked.
		raptor_world* rw = raptor_new_world();

		std::string mime_type = "application/sparql-results+xml";
		
		rdf::formatter f(*results, "", mime_type);

		// Set up serialiser
		http::response_serializer<http::empty_body> sr{res};

		// Start writing HTTP response.
		http::write_header(send, sr);

		// Create an HTTP response streamer and write.
		http_reply_stream<send_lambda&> strm(rw, send);

		f.write(strm, *results);

	    }
		    
	    return;
/*
    // Respond to HEAD request
    if(req.method() == http::verb::head)
    {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/plain");
        res.content_length(11);
        res.keep_alive(req.keep_alive());
        return send(std::move(res));
    }

    std::cout << "Body: " << req.body() << std::endl;

    // Respond to POST request
    http::response<http::string_body> res{
	http::status::ok, req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
//	{
//        std::piecewise_construct,
//        std::make_tuple(std::move(body)),
//        std::make_tuple(http::status::ok, req.version())};




    res.set(http::field::content_type, "text/plain");
    res.content_length(11);
    res.keep_alive(req.keep_alive());
    res.body() = "Hello world";
    return send(std::move(res));
*/
}

//------------------------------------------------------------------------------

// Handles an HTTP server connection
class session : public std::enable_shared_from_this<session>
{
public:
    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    std::shared_ptr<void> res_;
    send_lambda lambda_;

    sparql* s;
/*
    // This is the C++11 equivalent of a generic lambda.
    // The function object is used to send an HTTP message.
    struct send_lambda
    {
        session& self_;

        explicit
        send_lambda(session& self)
            : self_(self)
        {
        }

        template<bool isRequest, class Body, class Fields>
        void
        send_lambda::operator()(http::message<isRequest, Body, Fields>&& msg) const
        {
            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            self_.res_ = sp;

            // Write the response
            http::async_write(
                self_.stream_,
                *sp,
                beast::bind_front_handler(
                    &session::on_write,
                    self_.shared_from_this(),
                    sp->need_eof()));
        }

    };
*/
public:
    // Take ownership of the stream
    session(
        tcp::socket&& socket,
        sparql* s)
        : stream_(std::move(socket))
        , s(s)
        , lambda_(*this)
    {
    }

    // Start the asynchronous operation
    void
    run()
    {
        // We need to be executing within a strand to perform async operations
        // on the I/O objects in this session. Although not strictly necessary
        // for single-threaded contexts, this example code is written to be
        // thread-safe by default.
        net::dispatch(stream_.get_executor(),
                      beast::bind_front_handler(
                          &session::do_read,
                          shared_from_this()));
    }

    void
    do_read()
    {
        // Make the request empty before reading,
        // otherwise the operation behavior is undefined.
        req_ = {};

        // Set the timeout.
        stream_.expires_after(std::chrono::seconds(30));

        // Read a request
        http::async_read(stream_, buffer_, req_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    }

    void
    on_read(
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if(ec == http::error::end_of_stream)
            return do_close();

        if(ec)
            return fail(ec, "read");

        // Send the response
        handle_request(s, std::move(req_), lambda_);
    }

    void
    on_write(
        bool close,
        beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if(ec)
            return fail(ec, "write");

        if(close)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_close();
        }

        // We're done with the response so delete it
        res_ = nullptr;

        // Read another request
        do_read();
    }

    void
    do_close()
    {
        // Send a TCP shutdown
        beast::error_code ec;
        stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully
    }
};

        template<bool isRequest, class Body, class Fields>
        void
        send_lambda::operator()(http::message<isRequest, Body, Fields>&& msg) const
        {
            // The lifetime of the message has to extend
            // for the duration of the async operation so
            // we use a shared_ptr to manage it.
            auto sp = std::make_shared<
                http::message<isRequest, Body, Fields>>(std::move(msg));

            // Store a type-erased version of the shared
            // pointer in the class to keep it alive.
            self_.res_ = sp;

            // Write the response
            http::async_write(
                self_.stream_,
                *sp,
                beast::bind_front_handler(
                    &session::on_write,
                    self_.shared_from_this(),
                    sp->need_eof()));
        }

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
    net::io_context& ioc_;
    tcp::acceptor acceptor_;
    sparql* s;
public:
    listener(
        net::io_context& ioc,
        tcp::endpoint endpoint,
        sparql* s)
        : ioc_(ioc)
        , acceptor_(net::make_strand(ioc))
        , s(s)
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if(ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if(ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if(ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(
            net::socket_base::max_listen_connections, ec);
        if(ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void
    run()
    {
        do_accept();
    }

private:
    void
    do_accept()
    {
        // The new connection gets its own strand
        acceptor_.async_accept(
            net::make_strand(ioc_),
            beast::bind_front_handler(
                &listener::on_accept,
                shared_from_this()));
    }

    void
    on_accept(beast::error_code ec, tcp::socket socket)
    {
        if(ec)
        {
            fail(ec, "accept");
            return; // To avoid infinite loop
        }
        else
        {
            // Create the session and run it
            std::make_shared<session>(
                std::move(socket),
                s)->run();
        }

        // Accept another connection
        do_accept();
    }
};

//------------------------------------------------------------------------------


int main(int argc, char** argv)
{

    if (argc != 5) {
	std::cerr << "Usage:" << std::endl
		  << "\tsparql <port> <store> <storename> <threads>"
		  << std::endl;
	exit(1);
    }

    auto const address = net::ip::make_address("0.0.0.0");
    auto const port = static_cast<unsigned short>(std::atoi(argv[1]));
    auto const threads = std::max<int>(1, std::atoi(argv[4]));

    const std::string store(argv[2]);
    const std::string name(argv[3]);

    sparql s(store, name);

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // Create and launch a listening port
    std::make_shared<listener>(ioc, tcp::endpoint{address, port}, &s)->run();

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for(auto i = threads - 1; i > 0; --i)
        v.emplace_back(
        [&ioc]
        {
            ioc.run();
        });
    ioc.run();

    return 0;

}

