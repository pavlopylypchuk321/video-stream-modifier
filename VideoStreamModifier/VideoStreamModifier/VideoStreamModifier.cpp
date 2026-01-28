// Adds a prefix to the titles of HTML pages.
//

#include <crtdbg.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
#include <deque>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <cctype>
#include <process.h>

#include "ProtocolFilters.h"
#include "PFEventsDefault.h"

#include "samples_config.h"

#include "CompositeBuffer.h"

#pragma comment(lib, "ws2_32.lib")

using namespace nfapi;
using namespace ProtocolFilters;
using GoogleVideoMin::CompositeBuffer;

std::string g_titlePrefix;
std::string g_overlayText = "Custom Overlay";
std::string g_ffmpegPath = "ffmpeg.exe";  // Path to FFmpeg executable

// HTTP/1.1: ENDPOINT_ID -> FIFO of request URLs (best-effort; only reliable without pipelining)
static std::map<nfapi::ENDPOINT_ID, std::deque<std::string>> g_http1RequestQueue;
// HTTP/2: ENDPOINT_ID -> (streamId -> request URL)
static std::map<nfapi::ENDPOINT_ID, std::map<std::string, std::string>> g_http2StreamUrl;

// Structure to track video stream state per connection
struct VideoStreamBuffer {
    std::string contentType;
    std::string url;
    bool isVideoStream;
    size_t contentLength;  // Content-Length from header, 0 if chunked
    size_t processedSize;  // Amount of data already processed
    bool isProcessing;  // Flag to prevent concurrent processing
    
    VideoStreamBuffer() : isVideoStream(false), contentLength(0), processedSize(0), isProcessing(false) {}
};

class HttpFilter : public PFEventsDefault
{
private:
    std::map<nfapi::ENDPOINT_ID, VideoStreamBuffer> m_videoBuffers;

    struct UmpPart
    {
        int type;
        int size;
        CompositeBuffer data;
    };

    struct UmpAssembler
    {
        CompositeBuffer buffer;
        std::unordered_map<uint8_t, std::vector<uint8_t>> initByHeaderId;
        std::unordered_map<uint8_t, std::vector<uint8_t>> curByHeaderId;
        std::unordered_map<uint8_t, uint64_t> segIndexByHeaderId;
    };

    // Keyed by endpoint + (http2 stream id if present) + url (best-effort uniqueness)
    std::map<std::string, UmpAssembler> m_ump;
    std::map<std::string, size_t> m_umpProcessedSize;

    static bool readHeader(PFObject* object, int streamIndex, PFHeader& h)
    {
        PFStream* s = object->getStream(streamIndex);
        return s && pf_readHeader(s, &h);
    }

    static std::string getHttp2StreamId(PFObject* object)
    {
        // ProtocolFilters exposes HTTP/2 stream id in the HTTP2 info stream as "x-exhdr-streamid"
        PFHeader info;
        if (!readHeader(object, H2S_INFO, info))
            return "";

        PFHeaderField* f = info.findFirstField("x-exhdr-streamid");
        return f ? f->value() : "";
    }

    bool isVideoContentType(const std::string& contentType)
    {
        if (contentType.find("video/") != std::string::npos)
            return true;
        if (contentType.find("application/vnd.apple.mpegurl") != std::string::npos)  // HLS
            return true;
        if (contentType.find("application/vnd.yt-ump") != std::string::npos)  // UMP
            return true;
        if (contentType.find("application/dash+xml") != std::string::npos)  // DASH
            return true;
        return false;
    }

    bool isYouTubeVideoURL(const std::string& url)
    {
        return (url.find("googlevideo.com") != std::string::npos ||
                url.find("youtube.com") != std::string::npos ||
                url.find("ytimg.com") != std::string::npos);
    }

    // Overload that accepts already-read header (more efficient)
    std::string getURLFromHeader(PFObject* object, PFHeader* h)
    {
        if (!h)
            return "";

        std::string host, path, url;
        tPF_ObjectType objectType = object->getType();

        if (objectType == OT_HTTP_REQUEST)
        {
            // HTTP request - get host and path from headers
            PFHeaderField* pHostField = h->findFirstField("Host");
            if (pHostField)
                host = pHostField->value();
            
            // Get path from status line (first line: "GET /path HTTP/1.1")
            PFStream* pStatusStream = object->getStream(HS_STATUS);
            if (pStatusStream && pStatusStream->size() > 0)
            {
                std::vector<char> statusBuf((size_t)pStatusStream->size() + 1);
                pStatusStream->seek(0, FILE_BEGIN);
                pStatusStream->read(statusBuf.data(), (tStreamSize)pStatusStream->size());
                statusBuf[pStatusStream->size()] = '\0';
                
                std::string statusLine(statusBuf.data());
                // Parse "GET /path HTTP/1.1" format
                size_t firstSpace = statusLine.find(' ');
                if (firstSpace != std::string::npos)
                {
                    size_t secondSpace = statusLine.find(' ', firstSpace + 1);
                    if (secondSpace != std::string::npos)
                    {
                        path = statusLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
                    }
                }
            }
            
            if (!host.empty() && !path.empty())
            {
                url = "http://" + host + path;
            }
        }
        else if (objectType == OT_HTTP_RESPONSE)
        {
            // HTTP response - use custom headers that contain original request info
            PFHeaderField* pHostField = h->findFirstField("X-EXHDR-REQUEST-HOST");
            if (pHostField)
            {
                host = pHostField->value();
            }
            else
            {
                // Fallback: try regular Host header
                pHostField = h->findFirstField("Host");
                if (pHostField)
                    host = pHostField->value();
            }
            
            // Get original request line from custom header
            PFHeaderField* pRequestField = h->findFirstField("X-EXHDR-REQUEST");
            if (pRequestField)
            {
                std::string requestLine = pRequestField->value();
                
                // Parse request line: "GET /path HTTP/1.1" or "POST http://full.url/path HTTP/1.1"
                size_t firstSpace = requestLine.find(' ');
                if (firstSpace != std::string::npos)
                {
                    size_t secondSpace = requestLine.find(' ', firstSpace + 1);
                    if (secondSpace != std::string::npos)
                    {
                        path = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
                        
                        // Check if path already contains a full URL (starts with http:// or https://)
                        if (path.find("http://") == 0 || path.find("https://") == 0)
                        {
                            // Full URL already in path, use it directly
                            url = path;
                        }
                        else
                        {
                            // Relative path, construct URL from host + path
                            if (!host.empty())
                            {
                                url = "http://" + host + path;
                            }
                        }
                    }
                }
            }
        }
        else if (objectType == OT_HTTP2_REQUEST)
        {
            // HTTP/2 request
            PFHeaderField* pHostField = h->findFirstField(":authority");
            if (pHostField)
                host = pHostField->value();
            
            PFHeaderField* pPathField = h->findFirstField(":path");
            if (pPathField)
                path = pPathField->value();
            
            if (!host.empty() && !path.empty())
            {
                url = "http://" + host + path;
            }
        }
        else if (objectType == OT_HTTP2_RESPONSE)
        {
            // HTTP/2 response - ProtocolFilters exposes original request pseudo-headers as meta fields
            // (see PFFilterDefs.h): x-exhdr-authority, x-exhdr-path
            PFHeaderField* pHostField = h->findFirstField("x-exhdr-authority");
            if (pHostField)
                host = pHostField->value();

            PFHeaderField* pPathField = h->findFirstField("x-exhdr-path");
            if (pPathField)
                path = pPathField->value();

            if (!host.empty() && !path.empty())
                url = "http://" + host + path;
        }
        
        return url;
    }

    // Overload that reads header itself (for backward compatibility)
    std::string getURLFromHeader(PFObject* object)
    {
        PFHeader h;
        if (!pf_readHeader(object->getStream(HS_HEADER), &h))
        {
            return "";
        }
        return getURLFromHeader(object, &h);
    }

    static std::string sanitizeFilename(std::string s)
    {
        for (char &c : s)
        {
            if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.'))
                c = '_';
        }
        if (s.size() > 120) s.resize(120);
        return s;
    }

    static bool startsWithBoxType(const std::vector<uint8_t>& bytes, const char* type4)
    {
        // MP4 box: [0..3]=size, [4..7]=type
        if (bytes.size() < 8) return false;
        return bytes[4] == static_cast<uint8_t>(type4[0]) &&
               bytes[5] == static_cast<uint8_t>(type4[1]) &&
               bytes[6] == static_cast<uint8_t>(type4[2]) &&
               bytes[7] == static_cast<uint8_t>(type4[3]);
    }

    static bool looksLikeInitSegment(const std::vector<uint8_t>& bytes)
    {
        // Common init segment starts with ftyp then moov, but we just check leading ftyp/styp.
        return startsWithBoxType(bytes, "ftyp") || startsWithBoxType(bytes, "styp");
    }

    static void appendCompositeToVector(const CompositeBuffer& b, std::vector<uint8_t>& out)
    {
        for (const auto& ch : b.chunks)
            out.insert(out.end(), ch.begin(), ch.end());
    }

    static bool runFFmpegExtractFirstFramePPM(const std::string& inputMp4, const std::string& outPpm)
    {
        std::ostringstream cmd;
        cmd << g_ffmpegPath
            << " -hide_banner -loglevel error"
            << " -i \"" << inputMp4 << "\""
            << " -frames:v 1 -f image2 -vcodec ppm"
            << " -y \"" << outPpm << "\"";

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi{};
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

        std::string cmdStr = cmd.str();
        std::vector<char> cmdLine(cmdStr.begin(), cmdStr.end());
        cmdLine.push_back('\0');

        BOOL success = CreateProcessA(
            NULL,
            cmdLine.data(),
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (!success)
            return false;

        DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return (waitResult == WAIT_OBJECT_0);
    }

    static std::pair<int, int> readVarInt(const CompositeBuffer& buffer, int offset)
    {
        int byteLength;

        if (buffer.canReadBytes(offset, 1))
        {
            uint8_t firstByte = buffer.getUint8(offset);
            if (firstByte < 128)
                byteLength = 1;
            else if (firstByte < 192)
                byteLength = 2;
            else if (firstByte < 224)
                byteLength = 3;
            else if (firstByte < 240)
                byteLength = 4;
            else
                byteLength = 5;
        }
        else
        {
            byteLength = 0;
        }

        if (byteLength < 1 || !buffer.canReadBytes(offset, static_cast<size_t>(byteLength)))
            return { -1, offset };

        int value = 0;
        switch (byteLength)
        {
        case 1:
            value = buffer.getUint8(offset++);
            break;
        case 2:
        {
            int byte1 = buffer.getUint8(offset++);
            int byte2 = buffer.getUint8(offset++);
            value = (byte1 & 0x3f) + 64 * byte2;
            break;
        }
        case 3:
        {
            int byte1 = buffer.getUint8(offset++);
            int byte2 = buffer.getUint8(offset++);
            int byte3 = buffer.getUint8(offset++);
            value = (byte1 & 0x1f) + 32 * (byte2 + 256 * byte3);
            break;
        }
        case 4:
        {
            int byte1 = buffer.getUint8(offset++);
            int byte2 = buffer.getUint8(offset++);
            int byte3 = buffer.getUint8(offset++);
            int byte4 = buffer.getUint8(offset++);
            value = (byte1 & 0x0f) + 16 * (byte2 + 256 * (byte3 + 256 * byte4));
            break;
        }
        default:
        {
            // 5-byte encoding: 0xF0 then 4 bytes little-endian
            int tempOffset = offset + 1;
            buffer.focus(tempOffset);
            int b0 = buffer.getUint8(tempOffset);
            int b1 = buffer.getUint8(tempOffset + 1);
            int b2 = buffer.getUint8(tempOffset + 2);
            int b3 = buffer.getUint8(tempOffset + 3);
            value = b0 + 256 * (b1 + 256 * (b2 + 256 * b3));
            offset += 5;
            break;
        }
        }

        return { value, offset };
    }

    void consumeUmpParts(UmpAssembler& assem, const std::function<void(const UmpPart&)>& onPart)
    {
        while (true)
        {
            int offset = 0;
            auto [partType, newOffset] = readVarInt(assem.buffer, offset);
            offset = newOffset;

            if (partType < 0)
                break;

            auto [partSize, finalOffset] = readVarInt(assem.buffer, offset);
            offset = finalOffset;

            if (partSize < 0)
                break;

            if (!assem.buffer.canReadBytes(offset, static_cast<size_t>(partSize)))
                break;

            auto split1 = assem.buffer.split(static_cast<size_t>(offset)); // skip header
            auto split2 = split1.second.split(static_cast<size_t>(partSize));

            UmpPart p{ partType, partSize, split2.first };
            onPart(p);

            assem.buffer = split2.second;
        }
    }

    void handleUmpPart(UmpAssembler& assem, const UmpPart& part)
    {
        // Part IDs (from YouTube UMP): MEDIA=21, MEDIA_END=22
        const int UMP_PART_ID_MEDIA = 21;
        const int UMP_PART_ID_MEDIA_END = 22;

        if (part.type == UMP_PART_ID_MEDIA)
        {
            uint8_t headerId = part.data.getUint8(0);
            auto split = part.data.split(1);
            auto& cur = assem.curByHeaderId[headerId];
            appendCompositeToVector(split.second, cur);
        }
        else if (part.type == UMP_PART_ID_MEDIA_END)
        {
            uint8_t headerId = part.data.getUint8(0);
            auto it = assem.curByHeaderId.find(headerId);
            if (it == assem.curByHeaderId.end())
                return;

            std::vector<uint8_t> segment = std::move(it->second);
            assem.curByHeaderId.erase(it);

            if (segment.empty())
                return;

            if (looksLikeInitSegment(segment))
            {
                assem.initByHeaderId[headerId] = std::move(segment);
                printf("[UMP] Stored init segment for headerId=%u (%zu bytes)\n",
                    (unsigned)headerId, assem.initByHeaderId[headerId].size());
                return;
            }

            auto itInit = assem.initByHeaderId.find(headerId);
            if (itInit == assem.initByHeaderId.end() || itInit->second.empty())
            {
                printf("[UMP] No init segment yet for headerId=%u, skipping media fragment (%zu bytes)\n",
                    (unsigned)headerId, segment.size());
                return;
            }

            // Combine init + fragment (best-effort)
            std::vector<uint8_t> mp4;
            mp4.reserve(itInit->second.size() + segment.size());
            mp4.insert(mp4.end(), itInit->second.begin(), itInit->second.end());
            mp4.insert(mp4.end(), segment.begin(), segment.end());

            // Write to mp4 and extract first frame to PPM using ffmpeg.exe
            CreateDirectoryA("ump_output", NULL);
            uint64_t idx = assem.segIndexByHeaderId[headerId]++;
            std::ostringstream mp4Path, ppmPath;
            mp4Path << "ump_output\\h" << (unsigned)headerId << "_seg" << idx << ".mp4";
            ppmPath << "ump_output\\h" << (unsigned)headerId << "_seg" << idx << "_frame0.ppm";

            std::ofstream out(mp4Path.str(), std::ios::binary);
            out.write(reinterpret_cast<const char*>(mp4.data()), (std::streamsize)mp4.size());
            out.close();

            if (runFFmpegExtractFirstFramePPM(mp4Path.str(), ppmPath.str()))
            {
                printf("[UMP] Extracted first frame: %s\n", ppmPath.str().c_str());
            }
            else
            {
                printf("[UMP] FFmpeg frame extract failed for: %s\n", mp4Path.str().c_str());
            }
        }
    }

    bool processVideoWithFFmpeg(const char* inputData, size_t inputSize, 
                                 std::vector<char>& outputData)
    {
        char tempInputPath[MAX_PATH] = "";
        char tempOutputPath[MAX_PATH];
        GetTempFileNameA("TEMP", "vid", 0, tempInputPath);
        GetTempFileNameA("TEMP", "vid", 0, tempOutputPath);

        // Remove the ".tmp" extension
        std::string inputFile = tempInputPath;
        std::string outputFile = tempOutputPath;

        size_t dotPos = inputFile.rfind(".tmp");
        if (dotPos != std::string::npos) inputFile = inputFile.substr(0, dotPos);
        dotPos = outputFile.rfind(".tmp");
        if (dotPos != std::string::npos) outputFile = outputFile.substr(0, dotPos);

        // Add the extension you want
        inputFile += ".bin";
        outputFile += ".mp4";

        // Write input data to temp file
        std::ofstream inputStream(inputFile, std::ios::binary);
        if (!inputStream.is_open())
        {
            printf("Failed to create temp input file\n");
            return false;
        }
        inputStream.write(inputData, inputSize);
        inputStream.close();

        // Build FFmpeg command
        // Use fragmented MP4 for streaming compatibility
        std::ostringstream cmd;
        cmd << g_ffmpegPath << " -i \"" << inputFile << "\" "
            << "-vf \"drawtext=text='" << g_overlayText 
            << "':fontcolor=white:fontsize=24:x=10:y=10:box=1:boxcolor=black@0.5:boxborderw=2\" "
            << "-c:v libx264 -preset ultrafast -crf 23 -tune zerolatency "
            << "-c:a copy "
            << "-movflags frag_keyframe+empty_moov+faststart "
            << "-f mp4 -y \"" << outputFile << "\" 2>nul";

        // Execute FFmpeg
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        
        std::string cmdStr = cmd.str();
        char* cmdLine = new char[cmdStr.length() + 1];
        strcpy_s(cmdLine, cmdStr.length() + 1, cmdStr.c_str());

        BOOL success = CreateProcessA(
            NULL,
            cmdLine,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

        delete[] cmdLine;

        if (!success)
        {
            printf("Failed to start FFmpeg process\n");
            DeleteFileA(inputFile.c_str());
            return false;
        }

        // Wait for FFmpeg to complete (with timeout)
        DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);  // 30 second timeout
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        if (waitResult != WAIT_OBJECT_0)
        {
            printf("FFmpeg process timeout or error\n");
            DeleteFileA(inputFile.c_str());
            DeleteFileA(outputFile.c_str());
            return false;
        }

        // Read output file
        std::ifstream outputStream(outputFile, std::ios::binary | std::ios::ate);
        if (!outputStream.is_open())
        {
            printf("Failed to open output file\n");
            DeleteFileA(inputFile.c_str());
            DeleteFileA(outputFile.c_str());
            return false;
        }

        size_t outputSize = outputStream.tellg();
        outputStream.seekg(0, std::ios::beg);
        
        outputData.resize(outputSize);
        outputStream.read(outputData.data(), outputSize);
        outputStream.close();

        // Cleanup temp files
        DeleteFileA(inputFile.c_str());
        DeleteFileA(outputFile.c_str());

        return outputSize > 0;
    }

public:
    HttpFilter()
    {
    }

    // Offline / unit-test helper: feed raw UMP bytes and run the same extraction logic as live traffic.
    void debugProcessUmpBytes(const std::vector<uint8_t>& bytes, const std::string& key)
    {
        size_t& processed = m_umpProcessedSize[key];
        processed += bytes.size();

        UmpAssembler& assem = m_ump[key];
        assem.buffer.append(bytes);
        consumeUmpParts(assem, [&](const UmpPart& part) { handleUmpPart(assem, part); });
    }

    virtual void tcpClosed(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO /*pConnInfo*/)
    {
        // Clean up buffer when connection closes
        m_videoBuffers.erase(id);
        g_http1RequestQueue.erase(id);
        g_http2StreamUrl.erase(id);
    }

    virtual void tcpConnected(nfapi::ENDPOINT_ID id, nfapi::PNF_TCP_CONN_INFO pConnInfo)
    {
        if (pConnInfo->direction == NF_D_OUT)
        {
            pf_addFilter(id, FT_PROXY);
            pf_addFilter(id, FT_SSL, FF_SSL_INDICATE_HANDSHAKE_REQUESTS | FF_SSL_VERIFY | FF_SSL_TLS_AUTO);
            pf_addFilter(id, FT_HTTP, FF_HTTP_BLOCK_SPDY);
            pf_addFilter(id, FT_HTTP2);
        }
    }

    void dataAvailable(nfapi::ENDPOINT_ID id, PFObject* object)
    {
        tPF_ObjectType objType = object->getType();

        // --- Track requests ---
        if (objType == OT_HTTP_REQUEST)
        {
            PFHeader h;
            if (readHeader(object, HS_HEADER, h))
            {
                std::string url = getURLFromHeader(object, &h);
                if (!url.empty())
                {
                    g_http1RequestQueue[id].push_back(url);
                }
            }
        }
        else if (objType == OT_HTTP2_REQUEST)
        {
            PFHeader h;
            if (readHeader(object, H2S_HEADER, h))
            {
                std::string url = getURLFromHeader(object, &h);
                std::string sid = getHttp2StreamId(object);

                if (!sid.empty() && !url.empty())
                {
                    g_http2StreamUrl[id][sid] = url;
                }
            }
        }
 
        // Clean up buffer if this is the final data for a connection
        if (object->isReadOnly())
        {
            // Clean up buffer when connection is done
            m_videoBuffers.erase(id);
            g_http1RequestQueue.erase(id);
            g_http2StreamUrl.erase(id);
            return;
        }

        // --- Handle responses (video data is here) ---
        if (objType == OT_HTTP_RESPONSE || objType == OT_HTTP2_RESPONSE)
        {
            PFHeader h;
            const bool isHttp2 = (objType == OT_HTTP2_RESPONSE);
            const int headerIndex = isHttp2 ? H2S_HEADER : HS_HEADER;
            const int contentIndex = isHttp2 ? H2S_CONTENT : HS_CONTENT;

            if (readHeader(object, headerIndex, h))
            {
                PFHeaderField* pContentTypeField = h.findFirstField("Content-Type");

                std::string url = getURLFromHeader(object, &h); // often works due to X-EXHDR-* / x-exhdr-*

                // HTTP/2: match by stream id (responses may arrive out of order)
                if (isHttp2)
                {
                    std::string sid = getHttp2StreamId(object);
                    if (!sid.empty())
                    {
                        auto itConn = g_http2StreamUrl.find(id);
                        if (itConn != g_http2StreamUrl.end())
                        {
                            auto itSid = itConn->second.find(sid);
                            if (itSid != itConn->second.end())
                            {
                                url = itSid->second;
                                itConn->second.erase(itSid);
                            }
                        }
                    }
                }
                else
                {
                    // HTTP/1.1: responses are typically in-order, so consume FIFO to avoid unbounded growth.
                    auto it = g_http1RequestQueue.find(id);
                    if (it != g_http1RequestQueue.end() && !it->second.empty())
                    {
                        if (url.empty())
                        {
                            url = it->second.front();
                        }
                        it->second.pop_front();
                    }
                }
                
                // Check if this is a YouTube video response
                bool isYouTube = isYouTubeVideoURL(url);
                bool isVideo = pContentTypeField && isVideoContentType(pContentTypeField->value());
                
                if (pContentTypeField && isYouTube && isVideo)
                {
                    // Check if this is video content
                    PFStream* pStream = object->getStream(contentIndex);
                    if (pStream && pStream->size() > 0)
                    {
                        std::string contentType = pContentTypeField->value();

                        // --- UMP path: parse UMP and dump first decoded frame per completed segment ---
                        if (contentType.find("application/vnd.yt-ump") != std::string::npos)
                        {
                            std::string sid = isHttp2 ? getHttp2StreamId(object) : "";
                            std::ostringstream key;
                            key << id << ":" << (sid.empty() ? "h1" : sid) << ":" << sanitizeFilename(url);
                            std::string k = key.str();

                            size_t& processed = m_umpProcessedSize[k];
                            size_t currentSize = (size_t)pStream->size();
                            if (currentSize > processed)
                            {
                                size_t delta = currentSize - processed;
                                std::vector<uint8_t> newBytes(delta);
                                pStream->seek((tStreamPos)processed, FILE_BEGIN);
                                pStream->read(reinterpret_cast<char*>(newBytes.data()), (tStreamSize)delta);
                                processed = currentSize;

                                UmpAssembler& assem = m_ump[k];
                                assem.buffer.append(newBytes);

                                consumeUmpParts(assem, [&](const UmpPart& part) { handleUmpPart(assem, part); });
                            }
                        }
                        else
                        {
                            // --- Non-UMP path: apply overlay by remuxing with ffmpeg ---
                            size_t currentSize = (size_t)pStream->size();

                            std::vector<char> videoData(currentSize);
                            pStream->seek(0, FILE_BEGIN);
                            pStream->read(videoData.data(), (tStreamSize)currentSize);

                            std::vector<char> processedData;
                            if (processVideoWithFFmpeg(videoData.data(), videoData.size(), processedData))
                            {
                                pStream->reset();
                                pStream->write(processedData.data(), (tStreamSize)processedData.size());
                                printf("[dataAvailable] Video processed: %zu -> %zu bytes\n",
                                    videoData.size(), processedData.size());
                            }
                            else
                            {
                                printf("[dataAvailable] FFmpeg processing failed\n");
                            }
                        }
                    }
                }
            }
        }

        pf_postObject(id, object);
    }
};

int main(int argc, char* argv[])
{
    NF_RULE rule;

    g_titlePrefix = "Demo";
    g_titlePrefix += " ";
    g_overlayText = "Test Overlay";
    // Configure overlay text (can be set via command line or environment variable)
    

    // Configure FFmpeg path (can be set via environment variable)


    printf("Video Overlay Text: %s\n", g_overlayText.c_str());
    printf("FFmpeg Path: %s\n", g_ffmpegPath.c_str());
    printf("Starting video stream modifier...\n");

    // Offline debug mode: parse a dumped UMP file and extract frames into ./ump_output
    // Usage: VideoStreamModifier.exe --parse-ump path\to\dump.bin
    if (argc >= 3 && std::string(argv[1]) == "--parse-ump")
    {
        const char* path = argv[2];
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open())
        {
            printf("Failed to open UMP dump: %s\n", path);
            return 2;
        }
        std::streamsize sz = f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> data((size_t)sz);
        if (!f.read(reinterpret_cast<char*>(data.data()), sz))
        {
            printf("Failed to read UMP dump: %s\n", path);
            return 3;
        }

        HttpFilter offline;
        offline.debugProcessUmpBytes(data, "offline");
        printf("Done. Check .\\ump_output\\ for extracted segments/frames.\n");
        return 0;
    }

#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_CRT_DF);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

    nf_adjustProcessPriviledges();

    nf_setOptions(0, 0);

    printf("Press any key to stop...\n\n");

    HttpFilter f;

    pf_setRootSSLCertImportFlags(RSIF_PERSISTENT_CERTIFICATE_CACHE | RSIF_IMPORT_TO_MOZILLA_AND_OPERA);

    if (!pf_init(&f, L"c:\\netfilter2"))
    {
        printf("Failed to initialize protocol filter");
        return -1;
    }

    //	pf_setExceptionsTimeout(EXC_GENERIC, 30);
    //	pf_setExceptionsTimeout(EXC_TLS, 30);
    //	pf_setExceptionsTimeout(EXC_CERT_REVOKED, 30);

    pf_setRootSSLCertSubject("NFSDK Sample CA");

    // Initialize the library and start filtering thread
    if (nf_init(NFDRIVER_NAME, pf_getNFEventHandler()) != NF_STATUS_SUCCESS)
    {
        printf("Failed to connect to driver");
        return -1;
    }

    // Filter all TCP connections
    memset(&rule, 0, sizeof(rule));
    rule.direction = NF_D_OUT;
    rule.protocol = IPPROTO_TCP;
    rule.filteringFlag = NF_FILTER;
    nf_addRule(&rule, TRUE);

    // Block QUIC
    rule.direction = NF_D_BOTH;

    rule.protocol = IPPROTO_UDP;
    rule.remotePort = ntohs(80);
    rule.filteringFlag = NF_BLOCK;
    nf_addRule(&rule, TRUE);

    rule.protocol = IPPROTO_UDP;
    rule.remotePort = ntohs(443);
    rule.filteringFlag = NF_BLOCK;
    nf_addRule(&rule, TRUE);

    // Wait for any key
    getchar();

    // Free the libraries
    nf_free();
    pf_free();

    return 0;
}
