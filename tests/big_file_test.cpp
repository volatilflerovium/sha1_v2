#include <iostream>

#include "sha1/sha1.hpp"

//====================================================================

int main(int argc, char* argv[])
{
	const char* testFile="";
	if(argc==1){
		#ifndef TEST_FILE
			std::cout<<"No file provided.\n"
			return 0;
		#else
			testFile= TEST_FILE;
		#endif
	}
	else{
		testFile=argv[1];
	}

	SHA1 sha1;

	std::string hash;

	system("sha1sum  /tmp/1G_test_file.txt");
	if(sha1(testFile, hash)){
		std::cout<<hash<<"\n";
	}
	else{
		std::cout<<"Error: "<<sha1.getError()<<"\n";
	}

	return 0;
}
