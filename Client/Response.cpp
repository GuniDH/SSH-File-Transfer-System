#include "Response.h"
#include "Constants.h"
#include <boost/uuid/uuid_generators.hpp>
#include <boost/endian/conversion.hpp>

// With this logic, any request will be resent up to 3 *more* times if general error from server was received
Response::Response(boost::asio::ip::tcp::socket& s, const Request* r) {
	for (int i = 0; i < MAX_TRIES - 1; i++) { // MAX_TRIES - 1 because the first try was already done to get the error
		std::vector<uint8_t> header(RESPONSE_HEADER_SIZE);
		read(s, boost::asio::buffer(header));
		unpackHeader(header);
		if (code == REGISTRATION_FAILED_CODE)
			throw std::exception("Registration failed"); // In this case there's no sense trying to register again for 3 more times
		if (code == GENERAL_ERROR_CODE) {
			std::cerr << "server responded with an error" << std::endl;
			if (r != nullptr)
				r->send(s);
			continue;
		}
		return;
	}
	std::cerr << "server responded with an error" << std::endl;
	throw std::exception("Fatal error. Server responded with an error 4 times.\nPlease check your version and/or transfer.info file. You might have resent an existing file.");
	// The protocol didn't mention what to do in case a client resends an existing file which he already sent - I chose to return an error for this case and not allowing to overwrite.
}

Response::~Response() = default;

// Payload has to be read separately from header, because first we need to get payload size field from the header
void Response::initializePayload(boost::asio::ip::tcp::socket& s) {
	std::vector<uint8_t> payload(payloadSize);
	read(s, boost::asio::buffer(payload));
	unpackPayload(payload);
}

void Response::unpackHeader(const std::vector<uint8_t>& header) {
	std::copy_n(header.begin(), sizeof(version), &version);
	version = boost::endian::little_to_native(version);
	if (version != VERSION)
		throw std::runtime_error("Server version must be " + std::to_string(VERSION));
	std::copy_n(header.begin() + VERSION_SIZE, sizeof(code), reinterpret_cast<uint8_t*>(&code));
	code = boost::endian::little_to_native(code);
	std::copy_n(header.begin() + VERSION_SIZE + CODE_SIZE, sizeof(payloadSize), reinterpret_cast<uint8_t*>(&payloadSize));
	payloadSize = boost::endian::little_to_native(payloadSize);
}

uint16_t Response::getCode() const { return code; }
boost::uuids::uuid Response::getUUID() const { return uuid; }

RegistrationResponse::RegistrationResponse(boost::asio::ip::tcp::socket& s, const Request* r)
	: Response(s, r) {
	initializePayload(s);
}

void RegistrationResponse::unpackPayload(const std::vector<uint8_t>& payload)
{
	std::copy_n(payload.begin(), UUID_SIZE, uuid.begin());
}

AesResponse::AesResponse(boost::asio::ip::tcp::socket& s, const Request* r, std::string privateKey)
	: Response(s, r), privateKey(std::move(privateKey)) {
	initializePayload(s);
}

void AesResponse::unpackPayload(const std::vector<uint8_t>& payload)
{
	if (code == RECONNECTION_FAILED_CODE) // In this case there's no need in unpacking the payload
		return;
	std::copy_n(payload.begin(), UUID_SIZE, uuid.begin());
	std::string encryptedAES(payloadSize - UUID_SIZE, '\0');
	std::copy_n(payload.begin() + UUID_SIZE, payloadSize - UUID_SIZE, encryptedAES.begin());
	RSAPrivateWrapper rsaWrapper(privateKey);
	decryptedAES = rsaWrapper.decrypt(encryptedAES);
}

std::string AesResponse::getAES() const { return decryptedAES; }

FileReceivedResponse::FileReceivedResponse(boost::asio::ip::tcp::socket& s, const Request* r) : Response(s, r), contentSize(0), cksum(0) {
	initializePayload(s);
}

FileReceivedResponse::FileReceivedResponse(boost::asio::ip::tcp::socket& s) :Response(s, nullptr), contentSize(0), cksum(0) { initializePayload(s); }

void FileReceivedResponse::unpackPayload(const std::vector<uint8_t>& payload)
{
	std::copy_n(payload.begin(), UUID_SIZE, uuid.begin());
	std::copy_n(payload.begin() + UUID_SIZE, CONTENTSIZE_SIZE, reinterpret_cast<uint8_t*>(&contentSize));
	fileName.assign(reinterpret_cast<const char*>(payload.data() + UUID_SIZE + CONTENTSIZE_SIZE), FILE_NAME_SIZE);
	std::copy_n(payload.begin() + UUID_SIZE + CONTENTSIZE_SIZE + FILE_NAME_SIZE, CKSUM_SIZE, reinterpret_cast<uint8_t*>(&cksum));
}

uint32_t FileReceivedResponse::getContentSize() const { return contentSize; }

uint32_t FileReceivedResponse::getCRC() const { return cksum; }

std::string FileReceivedResponse::getFileName() const { return fileName; }

ReceivedMessageResponse::ReceivedMessageResponse(boost::asio::ip::tcp::socket& s, const Request* r)
	: Response(s, r) {
	initializePayload(s);
}

void ReceivedMessageResponse::unpackPayload(const std::vector<uint8_t>& payload)
{
	std::copy_n(payload.begin(), UUID_SIZE, uuid.begin());
}
