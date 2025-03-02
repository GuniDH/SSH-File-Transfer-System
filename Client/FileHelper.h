#pragma once
#include <boost/uuid/uuid.hpp>
#include <filesystem>
#include <tuple>


namespace fs = std::filesystem;

bool fileExists(const std::string& path);
std::string rstrip(const std::string& str);
std::tuple<std::string, std::string, std::string, std::string> interpretTransferFile();
void printHex(const std::string& str);
void writeHex(std::ofstream& file, const boost::uuids::uuid& uuid);
void writeMePrivFiles(const std::string& name, const boost::uuids::uuid& uuid, const std::string& privateKey);
const std::string getPrivKey();
const boost::uuids::uuid getUUID();
fs::path getExecutablePath();
uint32_t concatenateUint16ToUint32(uint16_t first, uint16_t second);