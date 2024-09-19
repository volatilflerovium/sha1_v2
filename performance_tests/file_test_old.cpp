#include "sha1_old_header_only.hpp"

int main(int argc, char* argv[])
{

#ifndef TEST_FILE
	const char* testFile=argv[1];
#else
	const char* testFile= TEST_FILE;
#endif

	SHA1::from_file(testFile);

	return 0;
}
