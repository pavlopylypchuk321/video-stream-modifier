#pragma once

#include "CompositeBuffer.h"

#include <cstdint>
#include <functional>

namespace GoogleVideoMin
{
    /**
     * Parses UMP binary stream and invokes callback with part_no, type, and size for each part.
     * Used by MITM to log UMP metadata without modifying the stream.
     */
    class UmpReader
    {
    public:
        explicit UmpReader(CompositeBuffer buffer);

        /**
         * Parses parts from the buffer and calls handlePart(partNo, type, size) for each complete part.
         * Stops when no complete part can be read (returns remaining buffer) or when buffer is exhausted.
         */
        void read(const std::function<void(int partNo, int type, int size)>& handlePart);

    private:
        std::pair<int, int> readVarInt(int offset) const;

        CompositeBuffer compositeBuffer;
    };
}
