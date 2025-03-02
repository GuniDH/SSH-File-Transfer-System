#pragma once
#include <boost/uuid/uuid.hpp>
#include <boost/asio.hpp>
#include <memory>
using boost::asio::ip::tcp;

class Client // Represents a client communicating with the server
{
private:
	boost::asio::io_context ioContext; // Keeping io_ctx and socket as fields so they won't get destructed when going back to main
	std::unique_ptr<tcp::socket> socket;
	boost::uuids::uuid uuid;
	std::string name;
	std::string decryptedAes;
	std::string fpath;
	std::string privateKey;

public:
	Client();
	void signup();
	void generateAndSendRSA();
	void login();
	void sendEncryptedFile();
};
