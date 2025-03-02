#include "SyntaxHelper.h"


bool isValidPort(const std::string& port) {
	try {
		int p = std::stoi(port);
		if (p < 0 && p > 65535 || port[0] == '0' && port.length() > 1)
			throw std::exception("Port should be integer between 0 to 65535");
		return true;
	}
	catch (...) {
		throw;
	}
}

bool isValidOctet(const std::string& octet) {
	try {
		int n = std::stoi(octet);
		if (n < 0 || n > 255 || octet[0] == '0' && octet.length() > 1)
			return false;
		return true;
	}
	catch (...) {
		throw;
	}
}

bool isValidIpv4(const std::string& ipv4) {
	// Split the IPv4 into octets
	std::stringstream ss(ipv4);
	std::string octet;
	bool validIPv4 = true;
	int octetCount = 0;
	// Validate each octet
	while (std::getline(ss, octet, '.')) {
		octetCount++;
		if (!isValidOctet(octet)) {
			validIPv4 = false;
			break;
		}
	}
	if (validIPv4 && octetCount == 4)
		return true;
	throw std::exception("IPv4 should be in format of n1.n2.n3.n4 such that ni(4 >= i >= 1) is an integer between 0 to 255");
}