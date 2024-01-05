#ifndef NETWORK_LAYER_ERROR_HPP
#define NETWORK_LAYER_ERROR_HPP

#include <string>

#include "type.hpp"

namespace pcap
{
class NetworkLayerError final
{
public:
	NetworkLayerError(NetworkLayerType type, std::string_view errorMsg) noexcept : type_{type}, errorMsg_{errorMsg.cbegin(), errorMsg.cend()} {}

	/**
   * @brief Returns an error message.
   * 
   * @return Error message
   */
	inline const std::string& error() const noexcept
	{
		return errorMsg_;
	}

	/**
   * @brief Returns the network layer view type.
   * 
   * @return Network layer view type 
   */
	inline NetworkLayerType type() const noexcept
	{
		return type_;
	}

private:
	NetworkLayerType type_;
	std::string errorMsg_;
};
} // namespace pcap

#endif // PACKET_NETWORK_LAYER_VIEW_ERROR_HPP
