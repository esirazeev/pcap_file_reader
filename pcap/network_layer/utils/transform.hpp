#ifndef NETWORK_LAYER_TRANSFORM_HPP
#define NETWORK_LAYER_TRANSFORM_HPP

#include "pcap/network_layer/layer.hpp"
#include "pcap/network_layer/type.hpp"

namespace pcap
{
class NetworkLayerTransformer final
{
public:
	[[nodiscard]] NetworkLayerInfo operator()(const Ethernet& header) const noexcept
	{
		return NetworkLayerInfo{.nextLayerType = header.type, .headerSize = sizeof(Ethernet)};
	}

	[[nodiscard]] NetworkLayerInfo operator()(const IPv4& header) const noexcept
	{
		return NetworkLayerInfo{.nextLayerType = header.protocol, .headerSize = sizeof(IPv4)};
	}

	[[nodiscard]] NetworkLayerInfo operator()(const Udp& header) const noexcept
	{
		return NetworkLayerInfo{.nextLayerType = static_cast<uint16_t>(NetworkLayerType::unsupported), .headerSize = sizeof(Udp)};
	}
};
} // namespace pcap

#endif // NETWORK_LAYER_TRANSFORM_HPP
