
// This is a wrapper around redland's raptor_iostream object to make it easier
// to interface with C++.
#ifndef IO_STRM_H
#define IO_STRM_H

#include <redland.h>

class io_strm {
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
    io_strm(raptor_world*);
    virtual ~io_strm();
		    
    virtual void init() {}
    virtual void finish() {}
    virtual void write(unsigned char byte) {
	int ret = write(&byte, 1);
	if (ret <= 0)
	    throw std::runtime_error("Write failed.");
    }

    virtual int write(unsigned char* bytes, unsigned int len) {}
    virtual void write_end() {}
    virtual int read(unsigned char* bytes, unsigned int len) {}
    virtual bool read_eof() {}

};

#endif

