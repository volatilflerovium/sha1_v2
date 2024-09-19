#include <iostream>

#include "sha1/sha1.hpp"

int main(int argc, char* argv[])
{

#ifndef TEST_FILE
	const char* testFile=argv[1];
#else
	const char* testFile= TEST_FILE;
#endif

	SHA1 sha1;

	std::string hash;

	if(!sha1(testFile, hash)){
		std::cout<<"Error: "<<sha1.getError()<<"\n";
	}

	return 0;
}
