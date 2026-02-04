#pragma once

#include "CompositeBuffer.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace GoogleVideoMin
{
    /**
     * Parses UMP binary stream and invokes callback with part_no, type, size, and payload for each part.
     */
    class UmpReader
    {
    public:
        explicit UmpReader(CompositeBuffer buffer);

        /**
         * Parses parts from the buffer and calls handlePart(partNo, type, size) for each complete part.
         */
        void read(const std::function<void(int partNo, int type, int size)>& handlePart);

        /**
         * Same as read() but passes part payload bytes to the callback for segment assembly.
         */
        void readWithData(const std::function<void(int partNo, int type, int size, const std::vector<uint8_t>& payload)>& handlePart);

    private:
        std::pair<int, int> readVarInt(int offset) const;

        CompositeBuffer compositeBuffer;
    };
}
