#include "FileHelper.h"
#include "Client.h"
#include "Request.h"
#include "Response.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Constants.h"
#include "cksum.h"
#include <files.h>
#include <cmath>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
using namespace CryptoPP;


Client::Client() {
	auto [ip, port, name, fpath] = interpretTransferFile();
	this->name = name;
	this->fpath = fpath;
	this->socket = std::make_unique<tcp::socket>(ioContext);
	tcp::resolver resolver(this->ioContext);
	boost::asio::connect(*socket, resolver.resolve(ip, port));
	if (!fileExists((getExecutablePath() / "me.info").string())) // If me file doesn't exist client has to sign up
		signup();
	else
		login();
}

// Signing up/Registration
void Client::signup() {
	std::cout << "Signing up" << std::endl;
	auto regReq = std::make_unique<RegistrationRequest>(name);
	regReq->send(*socket);
	std::cout << "Registration request sent" << std::endl;
	RegistrationResponse regRes(*socket, regReq.get());
	uuid = regRes.getUUID();
	std::cout << "UUID received: " << uuid << std::endl;
	generateAndSendRSA();
	writeMePrivFiles(name, uuid, privateKey); // Saving name, uuid, RSA private key in me.info and priv.key files
}

// Following the protocol, generating asymmetric RSA key, sending the public one to server and receiving symmetric AES key from it
void Client::generateAndSendRSA() {
	std::cout << "Generating RSA keys" << std::endl;
	RSAPrivateWrapper rsaWrapper;
	privateKey = rsaWrapper.getPrivateKey();
	auto pubkReq = std::make_unique<PublicKeyRequest>(uuid, name, rsaWrapper.getPublicKey());
	pubkReq->send(*socket);
	std::cout << "RSA Public key Sent: ";
	printHex(rsaWrapper.getPublicKey());
	std::cout<<std::endl;
	AesResponse aesRes(*socket, pubkReq.get(), privateKey);
	if (uuid != aesRes.getUUID()) // Validating uuid received from server to our correct uuid
		throw std::exception("Server provided bad UUID");
	decryptedAes = aesRes.getAES();
	std::cout << "AES received: " << std::endl;
	printHex(decryptedAes);
}

// Logging in and receiving symmetric AES key from server (using the same RSA keys that were generated while singing up prior to logging)
void Client::login() {
	std::cout << "Logging in" << std::endl;
	uuid = getUUID();
	std::cout << "UUID: " << uuid << std::endl;
	auto reconReq = std::make_unique<ReconnectionRequest>(uuid, name);
	reconReq->send(*socket);
	std::cout << "Reconnection request sent" << std::endl;
	AesResponse aesRes(*socket, reconReq.get(), getPrivKey());
	if (aesRes.getCode() == RECONNECTION_FAILED_CODE) {
		std::cout << "Reconnection failed" << std::endl;
		signup();
	}
	if (uuid != aesRes.getUUID()) // Validating uuid received from server to our correct uuid
		throw std::exception("Server provided bad UUID");
	decryptedAes = aesRes.getAES();
	std::cout << "AES received: " << std::endl;
	printHex(decryptedAes);
}

// Encrypting file and sending it to server
void Client::sendEncryptedFile() {
	std::string fileName = std::filesystem::path(fpath).filename().string();
	std::cout << "Encrypting and sending file " << fileName << std::endl;
	std::ifstream file(fpath, std::ios::binary | std::ios::in | std::ios::ate); // Using ate flag to open file at the end to get its size
	if (!file.is_open())
		throw std::runtime_error("Error opening file " + fileName);
	unsigned int origFileSize = file.tellg();
	std::vector<uint8_t> buffer(origFileSize);
	file.seekg(0, std::ios::beg); // Move to the beginning of file in order to read it
	if (!file.read(reinterpret_cast<char*>(buffer.data()), origFileSize))
		throw std::runtime_error("Error reading file " + fileName);
	file.close();
	for (int i = 0; i < MAX_TRIES; i++) {
		AESWrapper aesWrapper(reinterpret_cast<const unsigned char*>(decryptedAes.data()), static_cast<unsigned int>(decryptedAes.size()));
		std::string encryptedFile = aesWrapper.encrypt(reinterpret_cast<const char*>(buffer.data()), origFileSize);
		uint32_t encryptedFileSize = static_cast<uint32_t>(encryptedFile.length());
		size_t offset = 0;
		uint16_t packetNumber = 1;
		uint16_t totalPackets = static_cast<uint16_t>(std::ceil(static_cast<double>(encryptedFileSize / PACKET_SIZE)) + 1);
		for (size_t i = 0; i < totalPackets; i++) {
			size_t bytesToSend = std::min(static_cast<size_t>(PACKET_SIZE), encryptedFileSize - offset); // Choosing the minimum in case the last packet is smaller
			auto fpReq = std::make_unique<FilePacketRequest>(uuid, encryptedFileSize, origFileSize, concatenateUint16ToUint32(packetNumber, totalPackets), fileName, encryptedFile.substr(offset, bytesToSend));
			fpReq->send(*socket);
			ReceivedMessageResponse fpRes(*socket, fpReq.get()); // The protocol doesn't require a response here, but I chose to use it here in case there's error during sending file, such as the file already existing for client
			if (uuid != fpRes.getUUID()) // Validating uuid received from server to our correct uuid
				throw std::exception("Server provided bad UUID");
			std::cout << "Sent packet number " << packetNumber << " for file " << fileName << std::endl;
			offset += bytesToSend;
			packetNumber++;
		}
		FileReceivedResponse fileRecRes(*socket);
		// Validating fields that server provided
		if (fileRecRes.getContentSize() != encryptedFileSize) throw std::exception("Server provided faulty content size");
		if (fileRecRes.getFileName() != fileName) throw std::exception("Server provided faulty file name");
		if (to_string(fileRecRes.getUUID()) != to_string(uuid)) throw std::exception("Server provided faulty uuid");
		std::string decryptedFile(buffer.begin(), buffer.end()); // crc has to be checked on original (decrypted file) in order to validate the encryption process
		if (static_cast<unsigned long>(fileRecRes.getCRC()) == memcrc(const_cast<char*>(decryptedFile.c_str()), decryptedFile.size())) {
			auto doneValidReq = std::make_unique<DoneValidCRCRequest>(uuid, fileName);
			doneValidReq->send(*socket);
			ReceivedMessageResponse msgRes(*socket, doneValidReq.get());
			std::cout << "Sent file " << fileName << " successfully" << std::endl;
			return;
		}
		std::cout << "Trying to send file " << fileName << " again" << std::endl; // Will attempt to resend the file 3 more times, according to protocol
		auto resendingRequest = std::make_unique<ResendingFileInvalidCRCRequest>(uuid, fileName);
		resendingRequest->send(*socket); // Notifying the server client attempts to encrypt and send the file again
	}
	auto abortReq = std::make_unique<AbortInvalidCRCRequest>(uuid, fileName); // After 4 failed tries, client will abort
	abortReq->send(*socket);
	ReceivedMessageResponse msgRes(*socket, abortReq.get());
	throw std::runtime_error("Fatal error. Cannot send file " + fileName);
}
