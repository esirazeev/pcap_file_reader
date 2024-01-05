#ifndef NETWORK_LAYER_TYPE_HPP
#define NETWORK_LAYER_TYPE_HPP

#include <cstdint>
#include <span>

namespace pcap
{
enum class NetworkLayerType : uint16_t
{
	unsupported = 0x00,
	ethernet = 0x01,
	ip_v4 = 0x08,
	udp = 0x11
};

struct NetworkLayerInfo
{
	uint16_t nextLayerType;
	uint16_t headerSize;
};
} // namespace pcap

#endif // NETWORK_LAYER_TYPE_HPP
