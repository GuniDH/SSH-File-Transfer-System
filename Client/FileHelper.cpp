#include "FileHelper.h"
#include "SyntaxHelper.h"
#include "Base64Wrapper.h"
#include "Constants.h"
#include <string>
#include <regex>
#include <boost/uuid/string_generator.hpp>
#include <vector>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <windows.h>


// Returns true if the file exists and is accessible
bool fileExists(const std::string& path) {
	std::ifstream file(path);
	return file.good(); 
}

// Removes whitespaces from the right side of string
std::string rstrip(const std::string& str) {
	// Find the position of the last non-whitespace character
	auto end = str.find_last_not_of(" \t\n\r\f\v");
	if (end == std::string::npos)
		return "";  // Return an empty string if no non-whitespace character is found (all the string is whitespaces)
	return str.substr(0, end + 1);  // Return the substring up to the last non-whitespace character
}

// Using a tuple for shorter access to these fields on Client's constructor
std::tuple<std::string, std::string, std::string, std::string> interpretTransferFile() {
	fs::path exeDir = getExecutablePath();
	std::string transferPath = (exeDir / "transfer.info").string();
	if (!fileExists(transferPath))
		throw std::exception("Transfer file must exist for client");
	std::ifstream transfer(transferPath);
	if (!transfer.is_open())
		throw std::exception("Error opening transfer file");
	std::regex pattern(R"(\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:\s*(\d+)\s*)"); // Pattern to check if string fits IP format
	std::smatch match;
	std::vector<std::string>res;
	std::string line;
	size_t i;
	for (i = 0; i < 3 && std::getline(transfer, line); i++) {
		switch (i) {
		case 0: // IP and PORT
			if (std::regex_match(line, match, pattern)) {
				std::string ip = match[1];  // Extract IPv4 part
				std::string port = match[2];  // Extract port part
				if (!isValidIpv4(ip))
					throw std::exception("Ipv4 format is incorrect");
				if (!isValidPort(port))
					throw std::exception("Port format is incorrect");
				res.push_back(ip);
				res.push_back(port);
			}
			else
				throw std::exception("Format of first line in transfer file should be: 'ipv4 : port' such that whitespaces can be before ipv4, after port, between ipv4 and :, between : and port");
			break;
		case 1: // Name
			line = rstrip(line);
			if (line.length() <= NAME_MAX_LENGTH)
				res.push_back(line);
			else // In one place in the protocol it was mentioned the max length can be 255 and in another 100 was mentioned
				throw std::runtime_error("Name can be up to " + std::to_string(NAME_MAX_LENGTH) + " characters long");
			break;
		case 2: // File path
			line = rstrip(line);
			if (fileExists(line) && line.length() <= FILE_PATH_SIZE)
				res.push_back(line);
			else
				throw std::runtime_error("File doesn't exist or the path provided is too long (" + std::to_string(FILE_PATH_SIZE) + " characters max)");
			break;
		}
	}
	transfer.close();
	if (i != 3)
		throw std::exception("Error reading transfer file");
	return std::make_tuple(res[0], res[1], res[2], res[3]);
}

// Prints in hex format
void printHex(const std::string& str) {
	for (unsigned char byte : str) 
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
	std::cout << std::dec << std::endl; 
}

// Writes uuid in hex format to file
void writeHex(std::ofstream& file, const boost::uuids::uuid& uuid) {
	for (const auto& byte : uuid)
		file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
}

// Writes name,uuid,RSA private key to me.info and priv.key files, following the protocol (we can't use those fields from the client object when logging in because they were destructed)
void writeMePrivFiles(const std::string& name, const boost::uuids::uuid& uuid, const std::string& privateKey) {
	fs::path exeDir = getExecutablePath();
	std::string mePath = (exeDir / "me.info").string();
	std::string privPath = (exeDir / "priv.key").string();
	std::ofstream me(mePath);
	std::ofstream priv(privPath);
	if (!me.is_open())
		throw std::exception("Error opening me file");
	if (!priv.is_open())
		throw std::exception("Error opening private key file");
	me << name << std::endl;
	writeHex(me, uuid); // UUID should be written in hex format
	Base64Wrapper base64Wrapper; // RSA private key should be written in BASE64 format
	const std::string base64PrivKey = base64Wrapper.encode(privateKey);
	me << std::endl << base64PrivKey;
	priv << base64PrivKey;
	me.close();
	priv.close();
}

// Retrieves RSA private key from priv.key file
const std::string getPrivKey() {
	fs::path exeDir = getExecutablePath();
	std::string privPath = (exeDir / "priv.key").string();
	std::ifstream priv(privPath);
	if (!priv.is_open())
		throw std::exception("Error opening private key file");
	std::stringstream buffer;
	buffer << priv.rdbuf();
	priv.close();
	Base64Wrapper base64Wrapper;
	return base64Wrapper.decode(buffer.str());
}

// Retrieves uuid from me.info file
const boost::uuids::uuid getUUID() {
	fs::path exeDir = getExecutablePath();
	std::string mePath = (exeDir / "me.info").string();
	std::ifstream me(mePath);
	if (!me.is_open())
		throw std::exception("Error opening me file");
	std::string uuid;
	for (size_t i = 0; i < 2; i++) // UUID is at the second line
		if (!std::getline(me, uuid))
			throw std::exception("Error reading me file");
	me.close();
	return boost::uuids::string_generator()(uuid);
}

fs::path getExecutablePath() {
	char buffer[MAX_PATH]; // Buffer to store the path
	GetModuleFileNameA(NULL, buffer, MAX_PATH);  // Retrieves the full path of the executable
	fs::path exePath(buffer);  // Convert to fs::path
	return exePath.parent_path();  // Return the directory of the executable
}

// Packet num and total packet fields were asked by the protocol to be in the same 4 byte unit
uint32_t concatenateUint16ToUint32(uint16_t first, uint16_t second) {
	return (static_cast<uint32_t>(first) << 16) | static_cast<uint32_t>(second);
}