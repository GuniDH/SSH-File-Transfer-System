#include "Request.h"
#include "Constants.h"
#include <boost/uuid/uuid_generators.hpp>
#include <boost/endian/conversion.hpp>


void Request::send(boost::asio::ip::tcp::socket& s) const {
	try {
		write(s, boost::asio::buffer(header.data(), header.size()));
		write(s, boost::asio::buffer(payload.data(), payload.size()));
	}
	catch (...) {
		throw; // Throwing it to the main try-catch block
	}
}

void Request::packHeader(const boost::uuids::uuid& uuid, const uint16_t code, const uint32_t payloadSize) {
	header.resize(REQUEST_HEADER_SIZE);
	std::copy_n(uuid.begin(), UUID_SIZE, header.begin());
	header[UUID_SIZE] = VERSION;
	boost::endian::store_little_u16((header.data() + UUID_SIZE + VERSION_SIZE), code);
	boost::endian::store_little_u32((header.data() + UUID_SIZE + VERSION_SIZE + CODE_SIZE), payloadSize);
}

Request::~Request() = default;

void RegistrationRequest::packPayload(const std::string& name) {
	payload.resize(NAME_SIZE, NULLVAL);
	std::copy_n(name.begin(), std::min(name.size(), static_cast<size_t>(NAME_SIZE)), payload.begin());
}

RegistrationRequest::RegistrationRequest(const std::string& name) {
	packHeader(boost::uuids::nil_uuid(), REGISTRATION_CODE, NAME_SIZE);
	packPayload(name);
}

void PublicKeyRequest::packPayload(const std::string& name, const std::string& publicKey) {
	payload.resize(NAME_SIZE, NULLVAL);
	std::copy_n(name.begin(), std::min(name.size(), static_cast<size_t>(NAME_SIZE)), payload.begin());
	payload.insert(payload.end(), publicKey.begin(), publicKey.end());
}

PublicKeyRequest::PublicKeyRequest(const boost::uuids::uuid& uuid, const std::string& name, const std::string& publicKey) {
	packHeader(uuid, PUBLIC_KEY_CODE, NAME_SIZE + PUBLIC_KEY_SIZE);
	packPayload(name, publicKey);
}

void ReconnectionRequest::packPayload(const std::string& name) {
	payload.resize(NAME_SIZE, NULLVAL);
	std::copy_n(name.begin(), std::min(name.size(), static_cast<size_t>(NAME_SIZE)), payload.begin());
}

ReconnectionRequest::ReconnectionRequest(const boost::uuids::uuid& uuid, const std::string& name) { 
	packHeader(uuid, RECONNECTION_CODE, NAME_SIZE);
	packPayload(name);
}

void FilePacketRequest::packPayload(const uint32_t contentSize, const uint32_t origFileSize, const uint32_t packetNumTotalPackets, std::string& fname, const std::string& content) {
	payload.insert(payload.end(), reinterpret_cast<const uint8_t*>(&contentSize), reinterpret_cast<const uint8_t*>(&contentSize) + sizeof(contentSize));
	payload.insert(payload.end(), reinterpret_cast<const uint8_t*>(&origFileSize), reinterpret_cast<const uint8_t*>(&origFileSize) + sizeof(origFileSize));
	payload.insert(payload.end(), reinterpret_cast<const uint8_t*>(&packetNumTotalPackets), reinterpret_cast<const uint8_t*>(&packetNumTotalPackets) + sizeof(packetNumTotalPackets));
	fname.resize(FILE_NAME_SIZE, NULLVAL);
	payload.insert(payload.end(), fname.begin(), fname.end());
	payload.insert(payload.end(), content.begin(), content.end());
}

FilePacketRequest::FilePacketRequest(const boost::uuids::uuid& uuid, const uint32_t contentSize, const uint32_t origFileSize, const uint32_t packetNumTotalPackets, std::string& fname, const std::string& content) {
	packHeader(uuid, SENDING_FILE_CODE, SENDING_FILE_PAYLOAD_SIZE);
	packPayload(contentSize, origFileSize, packetNumTotalPackets, fname, content);
}

void DoneValidCRCRequest::packPayload(const std::string& fname) { 
	payload.resize(FILE_NAME_SIZE, NULLVAL);
	std::copy_n(fname.begin(), std::min(fname.size(), static_cast<size_t>(FILE_NAME_SIZE)), payload.begin());
}

DoneValidCRCRequest::DoneValidCRCRequest(const boost::uuids::uuid& uuid, const std::string& fname) { 
	packHeader(uuid, VALID_CRC_CODE, FILE_NAME_SIZE);
	packPayload(fname);
}

void ResendingFileInvalidCRCRequest::packPayload(const std::string& fname) { 
	payload.resize(FILE_NAME_SIZE, NULLVAL);
	std::copy_n(fname.begin(), std::min(fname.size(), static_cast<size_t>(FILE_NAME_SIZE)), payload.begin());
}

ResendingFileInvalidCRCRequest::ResendingFileInvalidCRCRequest(const boost::uuids::uuid& uuid, const std::string& fname) { 
	packHeader(uuid, INVALID_CRC_RESENDING_FILE_CODE, FILE_NAME_SIZE);
	packPayload(fname);
}

void AbortInvalidCRCRequest::packPayload(const std::string& fname) { 
	payload.resize(FILE_NAME_SIZE, NULLVAL);
	std::copy_n(fname.begin(), std::min(fname.size(), static_cast<size_t>(FILE_NAME_SIZE)), payload.begin());
}

AbortInvalidCRCRequest::AbortInvalidCRCRequest(const boost::uuids::uuid& uuid, const std::string& fname) { 
	packHeader(uuid, INVALID_CRC_ABORT_CODE, FILE_NAME_SIZE);
	packPayload(fname);
}
