#include "utils.hpp"
#include "deserializer.hpp"

namespace pcap
{
std::optional<NetworkLayer_t> getNetworkLayer(uint16_t type) noexcept
{
	switch (static_cast<NetworkLayerType>(type))
	{
	case NetworkLayerType::ethernet:
		return network_layer::Ethernet{};
	case NetworkLayerType::ip_v4:
		return network_layer::IPv4{};
	case NetworkLayerType::udp:
		return network_layer::Udp{};
	default:
		return {};
	}
}

int32_t deserializeNetworkLayer(NetworkLayer_t& layer, std::span<const uint8_t>& data, bool skipNetworkLayerInDataStream) noexcept
{
	auto [nextNetworkLayerType, NetworkLayerSize] = std::visit(Deserializer{}, layer, std::variant<std::span<const uint8_t>>{data});

	if (skipNetworkLayerInDataStream)
	{
		data = data.subspan(NetworkLayerSize, data.size() - NetworkLayerSize);
	}

	return nextNetworkLayerType;
}
} // namespace pcap
