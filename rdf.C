
#include <stdexcept>
#include "rdf.h"

using namespace rdf;

int iostream::io_init(void* ctxt)
{
    iostream* strm = (iostream*) ctxt;
    try {
	strm->init();
	return 0;
    } catch (...) {
	return -1;
    }
}

void iostream::io_finish(void* ctxt)
{
    iostream* strm = (iostream*) ctxt;
    try {
	strm->finish();
    } catch (...) {
    }
}

int iostream::io_write_byte(void* ctxt, const int byte)
{
    iostream* strm = (iostream*) ctxt;
    try {
	strm->write((unsigned char) byte);
	return 0;
    } catch (...) {
	return -1;
    }
}

int iostream::io_write_bytes(void* ctxt, const void* ptr,
			    size_t size, size_t nm)
{
    iostream* strm = (iostream*) ctxt;
    try {
	int ret =
	    strm->write((unsigned char*) ptr, size * nm);
	if (ret != (size * nm)) return -1;
	return 0;
    } catch (...) {
	return -1;
    }
}

int iostream::io_write_end(void* ctxt)
{
    iostream* strm = (iostream*) ctxt;
    try {
	strm->write_end();
	return 0;
    } catch (...) {
	return -1;
    }
}

int iostream::io_read_bytes(void* ctxt, void* ptr,
			   size_t size, size_t nm)
{
    iostream* strm = (iostream*) ctxt;
    try {
	int ret =
	    strm->read((unsigned char*) ptr, size * nm);
	if (ret != (size * nm)) return -1;
	return 0;
    } catch (...) {
	return -1;
    }
}

int iostream::io_read_eof(void* ctxt)
{
    iostream* strm = (iostream*) ctxt;
    try {
	bool ret = strm->read_eof();
	if (ret)
	    return true;
	return false;
    } catch (...) {
	return -1;
    }
}

iostream::iostream(raptor_world* rw)
{

    ioh.version = 2;
    ioh.init = &io_init;
    ioh.finish = &io_finish;
    ioh.write_byte = &io_write_byte;
    ioh.write_bytes = &io_write_bytes;
    ioh.write_end = &io_write_end;
    ioh.read_bytes = &io_read_bytes;
    ioh.read_eof = &io_read_eof;

    strm =
	raptor_new_iostream_from_handler(rw, (void*) this, &(ioh));

    if (strm == 0) {
	throw std::runtime_error("New raptor_stream failed");
    }

}

iostream::~iostream()
{
    if (strm) raptor_free_iostream(strm);
}

