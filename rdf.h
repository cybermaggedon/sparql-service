
#ifndef RDF_H
#define RDF_H

#include <redland.h>
#include <memory>

namespace rdf {

    class iostream {
      private:
	raptor_iostream_handler ioh;
    
      public:
	raptor_iostream* strm;
    
      private:    
	static int io_init(void* ctxt);
	static void io_finish(void* ctxt);
	static int io_write_byte(void* ctxt, const int byte);
	static int io_write_bytes(void* ctxt, const void* ptr,
				  size_t size, size_t nm);
	static int io_write_end(void* ctxt);
	static int io_read_bytes(void* ctxt, void* ptr,
				 size_t size, size_t nm);
	static int io_read_eof(void* ctxt);

      public:
	iostream(raptor_world*);
	virtual ~iostream();
		    
	virtual void init() {}
	virtual void finish() {}
	virtual void write(unsigned char byte) {
	    int ret = write(&byte, 1);
	    if (ret <= 0)
		throw std::runtime_error("Write failed.");
	}

	virtual int write(unsigned char* bytes, unsigned int len) {
	    return 0;
	}
	virtual void write_end() {}
	virtual int read(unsigned char* bytes, unsigned int len) {
	    return -1;
	}
	virtual bool read_eof() {
	    return true;
	}

    };

    class world {
      public:
	librdf_world* w;
        world() {
	    w = librdf_new_world();
	    if (w == nullptr) throw std::runtime_error("Couldn't create world");
	}
    };

    class storage {
      public:
	librdf_storage* s;
	world& w;
        storage(world& w, const std::string& store, const std::string& name) :
	w(w) {
	    s = librdf_new_storage(w.w, store.c_str(), name.c_str(), 0);
	    if (s == nullptr)
		throw std::runtime_error("Couldn't create storage.");
	}
    };

    class model {
      public:
	librdf_model* m;
	world& w;
        model(storage& s) : w(s.w) {
	    m = librdf_new_model(w.w, s.s, 0);
	    if (m == nullptr)
		throw std::runtime_error("Couldn't create model");
	}
    };

    class uri {
      public:
	librdf_uri* u;
	world& w;
        uri(world& w, const std::string& s) : w(w) {
	    const unsigned char* t =
		reinterpret_cast<const unsigned char*>(s.c_str());

	    u = librdf_new_uri(w.w, t);
	}
    };

    class stream {
      public:
	librdf_stream* str;
	stream(librdf_stream* str) {
	    this->str = str;
	}
	~stream() {
	    librdf_free_stream(str);
	}
    };

    class serializer {
      public:
	librdf_serializer* ser;
	serializer(world& w, const std::string& fmt) {
	    ser = librdf_new_serializer(w.w, fmt.c_str(), 0, 0);
	    if (ser == 0)
		throw std::runtime_error("Could not get serialiser.");
	}

	void write_stream_to_iostream(std::shared_ptr<stream> s,
				      rdf::iostream& out) {
	    int ret =
		librdf_serializer_serialize_stream_to_iostream(ser,
							       0,
							       s->str,
							       out.strm);
		if (ret < 0)
		    throw std::runtime_error("Serialisation failed.");

		// "This function ^^^ takes ownership of iostream and
		// frees it" says the docs.
		out.strm = nullptr;

	}
		
	~serializer() {
	    librdf_free_serializer(ser);
	}
    };
    
    class results {
      public:
	librdf_query_results* res;
	world& w;
        results(world& w, librdf_query_results* res) : w(w), res(res) {
	}
	~results() {
	    if (res)
		librdf_free_query_results(res);
	}
	bool is_graph() {
	    return librdf_query_results_is_graph(res) != 0;
	}
	bool is_bindings() {
	    return librdf_query_results_is_bindings(res) != 0;
	}
	bool is_boolean() {
	    return librdf_query_results_is_boolean(res) != 0;
	}

	std::shared_ptr<stream> as_stream() {
	    librdf_stream* str = librdf_query_results_as_stream(res);
	    if (str == 0)
		throw std::runtime_error("Could not get results as stream.");

	    return std::shared_ptr<stream>(new stream(str));
	}
	    
    };

    class query {
      public:
	librdf_query* q;
	world& w;
        query(world& w, const std::string& qry, uri& u) :
	w(w) {
	    const unsigned char* qs =
		reinterpret_cast<const unsigned char*>(qry.c_str());
	    q = librdf_new_query(w.w, "sparql", 0, qs, u.u);
	    if (q == 0)
		throw std::runtime_error("Couldn't create query");
	}
	std::shared_ptr<results> execute(model& m) {
	    librdf_query_results* r = librdf_query_execute(q, m.m);
	    if (r == nullptr)
		throw std::runtime_error("Query execution failed");
	    std::shared_ptr<results> res = std::make_shared<results>(w, r);
	    return res;
	}
	~query() {
	}

    };

    class formatter {
      public:
	librdf_query_results_formatter* f;
	formatter(results& res, const std::string& type,
		  const std::string& mime) {
	    if (type != "") {
		f = librdf_new_query_results_formatter2(res.res, type.c_str(),
							0, 0);
		if (f == 0)
		    throw std::runtime_error("Could not get formatter");
	    } else if (mime != "") {
		f = librdf_new_query_results_formatter2(res.res, 0,
							mime.c_str(),
							0);
		if (f == 0)
		    throw std::runtime_error("Could not get formatter");
	    } else
		throw std::runtime_error("Specify MIME or type");
	}
	~formatter() {
	    librdf_free_query_results_formatter(f);
	}

	void write(iostream& s, results& res) {
	    int ret =
		librdf_query_results_formatter_write(s.strm,
						     f,
						     res.res,
						     0);
		if (ret < 0)
		    throw std::runtime_error("Results format failed.");
	}

    };

};

#endif

