#ifndef Base64Tools_h
#define Base64Tools_h

#include <string>

namespace Base64Tools
{
	std::string base64_encode(unsigned char const*, unsigned int len);
	std::string base64_decode(std::string const& s);
};

#endif