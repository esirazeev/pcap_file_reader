#include <functional>

#include "deserialize.hpp"
#include "transform.hpp"
#include "utils.hpp"

namespace pcap
{
std::optional<NetworkLayer_t> getNetworkLayer(uint16_t type) noexcept
{
	switch (static_cast<NetworkLayerType>(type))
	{
	case NetworkLayerType::ethernet:
		return Ethernet{};
	case NetworkLayerType::ip_v4:
		return IPv4{};
	case NetworkLayerType::udp:
		return Udp{};
	default:
		return {};
	}
}

void deserializeNetworkLayer(std::span<const uint8_t> data, NetworkLayer_t& layer)
{
	std::visit(std::bind(NetworLayerDeserializer{}, data, std::placeholders::_1), layer);
}

NetworkLayerInfo retriveNetworkLayerInfo(const NetworkLayer_t& layer) noexcept
{
	return std::visit(NetworkLayerTransformer{}, layer);
}
} // namespace pcap
