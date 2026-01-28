#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace GoogleVideoMin
{
    class CompositeBuffer
    {
    public:
        using Chunk = std::vector<uint8_t>;

        CompositeBuffer();
        explicit CompositeBuffer(const std::vector<Chunk> &chunks);

        void append(const Chunk &chunk);
        void append(const CompositeBuffer &other);

        // Splits at position: returns pair {extracted, remaining}
        std::pair<CompositeBuffer, CompositeBuffer> split(size_t position) const;

        size_t getLength() const;
        bool canReadBytes(size_t position, size_t length) const;
        uint8_t getUint8(size_t position) const;

        void focus(size_t position) const;
        bool isFocused(size_t position) const;

        // Exposed internals
        std::vector<Chunk> chunks;
        mutable size_t currentChunkOffset;
        mutable size_t currentChunkIndex;

    private:
        size_t totalLength_;

        void resetFocus() const;
        bool canMergeWithLastChunk(const Chunk &chunk) const;
    };
}


