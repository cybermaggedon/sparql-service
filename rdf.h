
#ifndef RDF_H
#define RDF_H

#include <redland.h>

namespace rdf {

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

    class results {
      public:
	librdf_query_results* res;
	world& w;
        results(world& w, librdf_query_results* res) : w(w), res(res) {
	}
	~results() {
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
    };

    class query {
      public:
	librdf_query* q;
	world& w;
	results* res;
        query(world& w, const std::string& qry, uri& u) :
	w(w) {
	    const unsigned char* qs =
		reinterpret_cast<const unsigned char*>(qry.c_str());
	    q = librdf_new_query(w.w, "sparql", 0, qs, u.u);
	    res = 0;
	    if (q == 0)
		throw std::runtime_error("Couldn't create query");
	}
	results& execute(model& m) {
	    librdf_query_results* r = librdf_query_execute(q, m.m);
	    if (r == nullptr)
		throw std::runtime_error("Query execution failed");
	    res = new results(w, r);
	    return *res;
	}
	~query() {
	    if (res) delete res;
	}

    };

    

};

#endif

