#ifndef PCAP_NETWORK_LAYER_DESERIALIZER_HPP
#define PCAP_NETWORK_LAYER_DESERIALIZER_HPP

#include <cstring>
#include <span>

#include "network_layers.hpp"
#include "pcap/utils/byte_swapper.hpp"

namespace pcap
{
class Deserializer final
{
public:
	std::pair<int32_t, int32_t> operator()(network_layer::Ethernet& ethernet, std::span<const uint8_t> data) const noexcept
	{
		auto nextNetworkType{-1};

		if (deserialize(ethernet, data))
		{
			nextNetworkType = ethernet.type;
		}

		return {nextNetworkType, sizeof(network_layer::Ethernet)};
	}

	std::pair<int32_t, int32_t> operator()(network_layer::IPv4& ipv4, std::span<const uint8_t> data) const noexcept
	{
		auto nextNetworkType{-1};

		if (deserialize(ipv4, data))
		{
			nextNetworkType = ipv4.protocol;
		}

		return {nextNetworkType, sizeof(network_layer::IPv4)};
	}

	std::pair<int32_t, int32_t> operator()(network_layer::Udp& udp, std::span<const uint8_t> data) const noexcept
	{
		auto nextNetworkType{-1};

		if (deserialize(udp, data))
		{
			nextNetworkType = static_cast<int32_t>(NetworkLayerType::unsupported);
		}

		return {nextNetworkType, sizeof(network_layer::Udp)};
	}

private:
	template <typename T>
	static bool deserialize(T& obj, std::span<const uint8_t>& data) noexcept
	{
		if (data.size() < sizeof(T)) [[unlikely]]
		{
			return false;
		}

		std::memcpy(&obj, data.data(), sizeof(T));
		ByteSwapper{}(obj);

		return true;
	}
};
} // namespace pcap

#endif // PCAP_UTILS_DESERIALIZER_HPP
