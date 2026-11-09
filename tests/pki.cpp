#include "pki_selftest.h"
#include <iostream>
int main(){std::string error;if(!pkiSelfTest(error)){std::cerr<<"PKI self-test failed: "<<error<<'\n';return 1;}std::cout<<"EMV RSA certificate/DDA/fDDA positive and negative tests passed\n";}
