// Client for RSA encrypted file transfer system
// Author: Guni 


#include "Client.h"
#include <iostream>


int main()
{
	try
	{
		const auto client = std::make_unique<Client>();
		client->sendEncryptedFile();
		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "Exception: " << e.what() << std::endl;
		return 1;
	}
}
