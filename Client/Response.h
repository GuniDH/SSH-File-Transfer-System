#pragma once
#include "Request.h"
#include "RSAWrapper.h"
#include "FileHelper.h"
#include <boost/uuid/uuid.hpp>
#include <boost/asio.hpp>


// I constructed the code in such way that doesn't require having an inheriting class for each type of response.
// For instance, taking care of reconnection failed response is enough to do just at the unpackPayload function of AESResponse.
class Response { // Represents a response from server to client
protected:
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;
	boost::uuids::uuid uuid;
	void unpackHeader(const std::vector<uint8_t>& header);
	virtual void unpackPayload(const std::vector<uint8_t>& payload) = 0;
public:
	virtual ~Response();
	Response(boost::asio::ip::tcp::socket& s, const Request* r);
	void initializePayload(boost::asio::ip::tcp::socket& s);
	uint16_t getCode() const;
	boost::uuids::uuid getUUID() const;
};

class RegistrationResponse : public Response {
private:
	void unpackPayload(const std::vector<uint8_t>& payload) override;
public:
	RegistrationResponse(boost::asio::ip::tcp::socket& s, const Request* r);
};

class AesResponse : public Response {
private:
	std::string privateKey;
	std::string decryptedAES;
	void unpackPayload(const std::vector<uint8_t>& payload) override;
public:
	AesResponse(boost::asio::ip::tcp::socket& s, const Request* r, std::string privateKey);
	std::string getAES() const;
};

class FileReceivedResponse : public Response {
private:
	uint32_t contentSize;
	uint32_t cksum;
	std::string fileName;
	void unpackPayload(const std::vector<uint8_t>& payload) override;
public:
	FileReceivedResponse(boost::asio::ip::tcp::socket& s, const Request* r);
	FileReceivedResponse(boost::asio::ip::tcp::socket& s);
	uint32_t getContentSize() const;
	uint32_t getCRC() const;
	std::string getFileName() const;
};

class ReceivedMessageResponse : public Response {
private:
	void unpackPayload(const std::vector<uint8_t>& payload) override;
public:
	ReceivedMessageResponse(boost::asio::ip::tcp::socket& s, const Request* r);
};
