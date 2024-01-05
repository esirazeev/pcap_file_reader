#ifndef NETWORK_LAYER_UTILS_HPP
#define NETWORK_LAYER_UTILS_HPP

#include <optional>
#include <span>
#include <variant>

#include "pcap/network_layer/layer.hpp"
#include "pcap/network_layer/type.hpp"

namespace pcap
{
using NetworkLayer_t = std::variant<Ethernet, IPv4, Udp>;

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
 * @param data Data stream
 * @param layer Network layer
 */
void deserializeNetworkLayer(std::span<const uint8_t> data, NetworkLayer_t& layer);

/**
 * @brief Retrieves network layer information.
 * 
 * @param layer Network layer
 * 
 * @return Network layer information 
 */
[[nodiscard]] NetworkLayerInfo retriveNetworkLayerInfo(const NetworkLayer_t& layer) noexcept;
} // namespace pcap

#endif // NETWORK_LAYER_UTILS_HPP
