#pragma once
#include <boost/uuid/uuid.hpp>
#include <boost/asio.hpp>
#include <vector>
#include <string>


class Request { // Represents a request from client to server
protected:
	std::vector<uint8_t> header;
	std::vector<uint8_t> payload;
	void packHeader(const boost::uuids::uuid& uuid, const uint16_t code, const uint32_t payloadSize);

public:
	virtual ~Request();
	void send(boost::asio::ip::tcp::socket& s) const;
};

class RegistrationRequest : public Request {
private:
	void packPayload(const std::string& name);

public:
	RegistrationRequest(const std::string& name);
};

class PublicKeyRequest : public Request {
private:
	void packPayload(const std::string& name, const std::string& publicKey);

public:
	PublicKeyRequest(const boost::uuids::uuid& uuid, const std::string& name, const std::string& publicKey);
};

class ReconnectionRequest : public Request {
private:
	void packPayload(const std::string& name);

public:
	ReconnectionRequest(const boost::uuids::uuid& uuid, const std::string& name);
};

class FilePacketRequest : public Request {
private:
	void packPayload(const uint32_t contentSize, const uint32_t origFileSize, const uint32_t packetNumTotalPackets, std::string& fname, const std::string& content);

public:
	FilePacketRequest(const boost::uuids::uuid& uuid, const uint32_t contentSize, const uint32_t origFileSize, const uint32_t packetNumTotalPackets, std::string& fname, const std::string& content);
};

class DoneValidCRCRequest : public Request {
private:
	void packPayload(const std::string& fname);

public:
	DoneValidCRCRequest(const boost::uuids::uuid& uuid, const std::string& fname);
};

class ResendingFileInvalidCRCRequest : public Request {
private:
	void packPayload(const std::string& fname);

public:
	ResendingFileInvalidCRCRequest(const boost::uuids::uuid& uuid, const std::string& fname);
};

class AbortInvalidCRCRequest : public Request {
private:
	void packPayload(const std::string& fname);

public:
	AbortInvalidCRCRequest(const boost::uuids::uuid& uuid, const std::string& fname);
};
