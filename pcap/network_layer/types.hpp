#ifndef PCAP_NETWORK_LAYER_TYPES_HPP
#define PCAP_NETWORK_LAYER_TYPES_HPP

#include <variant>

#include "network_layers.hpp"

namespace pcap
{
enum class NetworkLayerType : uint16_t
{
	unsupported = 0x00,
	ethernet = 0x01,
	ip_v4 = 0x08,
	udp = 0x11
};

using NetworkLayer_t = std::variant<network_layer::Ethernet, network_layer::IPv4, network_layer::Udp>;
} // namespace pcap

#endif // PCAP_NETWORK_LAYER_TYPES_HPP
