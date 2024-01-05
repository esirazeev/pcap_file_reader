#ifndef PCAP_NETWORK_LAYER_UTILS_HPP
#define PCAP_NETWORK_LAYER_UTILS_HPP

#include <optional>
#include <span>

#include "types.hpp"

namespace pcap
{
/**
 * @brief Returns the network layer from type.
 * 
 * @param type Network layer type
 * 
 * @return Network layer if supported, otherwie - std::nullopt
 */
[[nodiscard]] std::optional<NetworkLayer_t> getNetworkLayer(uint16_t type) noexcept;

/**
 * @brief Deserializes the network layer from a data stream.
 * 
 * @param layer Network layer
 * @param data Data stream
 * @param skipNetworkLayerInDataStream Indicates that the network layer will be skipped in the data stream
 * 
 * @return Next network layer type if deserialization was successful, otherwise `-1`
 */
int32_t deserializeNetworkLayer(NetworkLayer_t& layer, std::span<const uint8_t>& data, bool skipNetworkLayerInDataStream = false) noexcept;
} // namespace pcap

#endif // PCAP_NETWORK_LAYER_UTILS_HPP
