#include <cstring>
#include <format>
#include <iostream>

#include "packet.hpp"
#include "pcap/network_layer/utils.hpp"

namespace pcap
{
Packet::Packet() noexcept : linkLayerType_{} {}

Packet::Packet(Packet&& packet) noexcept : linkLayerType_{}
{
	std::swap(buffer_, packet.buffer_);
	std::swap(layers_, packet.layers_);
	std::swap(timestamp_, packet.timestamp_);
	std::swap(payload_, packet.payload_);
	std::swap(linkLayerType_, packet.linkLayerType_);
}

Packet& Packet::operator=(Packet&& packet) noexcept
{
	if (this != &packet)
	{
		buffer_ = std::move(packet.buffer_);
		layers_ = std::move(packet.layers_);
		timestamp_ = std::move(packet.timestamp_);
		payload_ = std::move(packet.payload_);

		linkLayerType_ = packet.linkLayerType_;
		packet.linkLayerType_ = 0;
	}

	return *this;
}

void Packet::fill(const std::chrono::nanoseconds& timestamp, uint32_t linkLayerType, const byte_buffer::ByteBuffer& buffer)
{
	timestamp_ = timestamp;
	linkLayerType_ = linkLayerType;
	buffer_ = buffer;
}

void Packet::fill(const std::chrono::nanoseconds& timestamp, uint32_t linkLayerType, byte_buffer::ByteBuffer&& buffer)
{
	timestamp_ = timestamp;
	linkLayerType_ = linkLayerType;
	buffer_ = std::move(buffer);
}

uint64_t Packet::timestamp() const noexcept
{
	return timestamp_.count();
}

uint16_t Packet::size() const noexcept
{
	return buffer_.size();
}

bool Packet::parse() noexcept
{
	layers_.clear();
	payload_ = buffer_.data();

	auto networkLayerType{static_cast<int32_t>(linkLayerType_)};

	do
	{
		auto layer{getNetworkLayer(networkLayerType)};

		if (not layer)
		{
			std::cerr << std::format("pcap::Packet: unsupported network layer {}\n", networkLayerType);
			return false;
		}

		networkLayerType = deserializeNetworkLayer(*layer, payload_, true);

		if (networkLayerType == -1)
		{
			std::cerr << "pcap::Packet: cannot deserialize network layer: file corrupted\n";
			return false;
		}

		layers_.push_back(*layer);
	} while (networkLayerType != static_cast<uint16_t>(NetworkLayerType::unsupported));

	return true;
}

const NetworkLayer_t* Packet::firstLayer() const noexcept
{
	return layers_.empty() ? nullptr : &layers_.front();
}

const NetworkLayer_t* Packet::lastLayer() const noexcept
{
	return layers_.empty() ? nullptr : &layers_.back();
}

const std::vector<NetworkLayer_t>& Packet::layers() const noexcept
{
	return layers_;
}

std::span<const uint8_t> Packet::payload() const noexcept
{
	return payload_;
}
} // namespace pcap
