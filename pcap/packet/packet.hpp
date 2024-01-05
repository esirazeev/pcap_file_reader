#ifndef PCAP_PACKET_HPP
#define PCAP_PACKET_HPP

#include <cstdint>
#include <vector>

#include "byte_buffer/byte_buffer.hpp"
#include "pcap/network_layer/utils/utils.hpp"

namespace pcap
{
class Packet final
{
public:
	Packet() noexcept;
	Packet(const Packet&) = delete;
	Packet(Packet&&) noexcept;
	Packet& operator=(const Packet&) = delete;
	Packet& operator=(Packet&&) noexcept;
	~Packet() = default;

	/**
	 * @brief Fills out the packet.
	 * 
	 * @param timestampNanoSec Timestamp `nanoseconds`
	 * @param linkLayerType Link layer type
	 * @param buffer Byte buffer
	 * 
	 * @return `True` if the package was successfully filled, otherwise - `false`
	 */
	void fill(uint64_t timestampNanoSec, uint32_t linkLayerType, const byte_buffer::ByteBuffer& buffer);

	/**
	 * @brief Fills out the packet.
	 * 
	 * @param timestampNanoSec Timestamp `nanoseconds`
	 * @param linkLayerType Link layer type
	 * @param buffer Byte buffer
	 * 
	 * @return `True` if the package was successfully filled, otherwise - `false`
	 */
	void fill(uint64_t timestampNanoSec, uint32_t linkLayerType, byte_buffer::ByteBuffer&& buffer);

	/**
	 * @brief Returns the packet timestamp.
	 * 
	 * @return Packet timestamp `nanoseconds`
	 */
	[[nodiscard]] uint64_t timestamp() const noexcept;

	/**
	 * @brief Returns the packet size.
	 * 
	 * @return Packet size
	 */
	[[nodiscard]] uint16_t size() const noexcept;

	/**
	 * @brief Parses packet network layers.
	 * 
	 * @return `True` if parsing the network layers of the package was successful, otherwise - `false`
	 */
	[[nodiscard]] bool parse() noexcept;

	/**
	 * @brief Returns the first network layer of a packet.
	 * 
	 * @return First packet network layer
	 */
	[[nodiscard]] const NetworkLayer_t* firstLayer() const noexcept;

	/**
	 * @brief Returns the last network layer of a packet 
	 * 
	 * @return Last packet network layer
	 */
	[[nodiscard]] const NetworkLayer_t* lastLayer() const noexcept;

	/**
	 * @brief Returns network layers of a packet.
	 * 
	 * @return Packet network layers
	 */
	[[nodiscard]] const std::vector<NetworkLayer_t>& layers() const noexcept;

	/**
	 * @brief Returns the packet payload.
	 * 
	 * @return Packet payload 
	 */
	[[nodiscard]] std::span<const uint8_t> payload() const noexcept;

private:
	byte_buffer::ByteBuffer buffer_;
	std::vector<NetworkLayer_t> layers_;
	uint32_t linkLayerType_;
	uint64_t timestampNanoSec_;
	std::span<const uint8_t> payload_;
};
} // namespace pcap

#endif
