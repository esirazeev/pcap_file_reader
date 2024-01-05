#ifndef PCAP_NETWORK_LAYERS_HPP
#define PCAP_NETWORK_LAYERS_HPP

#include <cstdint>

namespace pcap
{
namespace network_layer
{
#pragma pack(push, 1)

struct Ethernet
{
	uint8_t destination[6];
	uint8_t source[6];
	uint16_t type;
};

struct IPv4
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t headerLength : 4;
	uint8_t version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version : 4;
	uint8_t headerLength : 4;
#endif
	uint8_t serviceType;
	uint16_t totalLength;
	uint16_t identification;
	uint16_t flagsOffset;
	uint8_t timeToLive;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t sourceAddress;
	uint32_t destinationAddress;
};

struct Udp
{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint16_t length;
	uint16_t checksum;
};

#pragma pack(pop)
} // namespace network_layer
} // namespace pcap

#endif // PCAP_NETWORK_LAYERS_HPP
