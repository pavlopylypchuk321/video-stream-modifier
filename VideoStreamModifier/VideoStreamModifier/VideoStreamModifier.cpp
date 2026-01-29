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

// FFmpeg library headers (we use the libraries directly instead of the CLI)
extern "C" {
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#include <libavutil/opt.h>
#include <libavutil/imgutils.h>
}

// Link against FFmpeg import libraries (Visual Studio)
#pragma comment(lib, "avformat.lib")
#pragma comment(lib, "avcodec.lib")
#pragma comment(lib, "avutil.lib")
#pragma comment(lib, "swscale.lib")

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

    struct MediaHeaderMeta
    {
        bool hasIsInitSeg = false;
        bool isInitSeg = false;
        bool hasItag = false;
        int32_t itag = 0;
        bool hasSeq = false;
        int32_t sequenceNumber = 0;
    };

    struct UmpPart
    {
        int type;
        int size;
        CompositeBuffer data;
    };

    struct UmpAssembler
    {
        CompositeBuffer buffer;
        std::unordered_map<uint8_t, MediaHeaderMeta> metaByHeaderId;
        std::unordered_map<uint8_t, std::vector<uint8_t>> initByHeaderId;
        std::unordered_map<int32_t, std::vector<uint8_t>> initByItag;
        std::unordered_map<uint8_t, std::vector<uint8_t>> curByHeaderId;
        std::unordered_map<uint8_t, std::vector<std::vector<uint8_t>>> pendingByHeaderId;
        std::unordered_map<uint8_t, uint64_t> segIndexByHeaderId;

        // Rewritten UMP bytes (we re-emit parts after processing instead of
        // forwarding the original bytes directly).
        std::vector<uint8_t> rewrittenUmpOut;
        // Number of bytes already sent downstream from rewrittenUmpOut.
        size_t rewrittenSentOffset = 0;
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
        // Common init segment starts with ftyp then moov, but YouTube init segments sometimes
        // begin with other boxes. We keep this as a heuristic fallback only.
        return startsWithBoxType(bytes, "ftyp") || startsWithBoxType(bytes, "styp") || startsWithBoxType(bytes, "moov");
    }

    static void appendCompositeToVector(const CompositeBuffer& b, std::vector<uint8_t>& out)
    {
        for (const auto& ch : b.chunks)
            out.insert(out.end(), ch.begin(), ch.end());
    }

    static std::vector<uint8_t> compositeToVector(const CompositeBuffer& b)
    {
        std::vector<uint8_t> out;
        out.reserve(b.getLength());
        appendCompositeToVector(b, out);
        return out;
    }

    static bool pbReadVarint(const std::vector<uint8_t>& bytes, size_t& i, uint64_t& out)
    {
        out = 0;
        int shift = 0;
        while (i < bytes.size() && shift <= 63)
        {
            uint8_t c = bytes[i++];
            out |= (uint64_t)(c & 0x7F) << shift;
            if ((c & 0x80) == 0)
                return true;
            shift += 7;
        }
        return false;
    }

    static bool pbSkipField(const std::vector<uint8_t>& bytes, size_t& i, uint32_t wireType)
    {
        switch (wireType)
        {
        case 0: { // varint
            uint64_t tmp;
            return pbReadVarint(bytes, i, tmp);
        }
        case 1: // 64-bit
            if (i + 8 > bytes.size()) return false;
            i += 8;
            return true;
        case 2: { // length-delimited
            uint64_t len;
            if (!pbReadVarint(bytes, i, len)) return false;
            if (i + (size_t)len > bytes.size()) return false;
            i += (size_t)len;
            return true;
        }
        case 5: // 32-bit
            if (i + 4 > bytes.size()) return false;
            i += 4;
            return true;
        default:
            return false;
        }
    }

    // --- Minimal UMP writer (local; mirrors googlevideo-c/googlevideo/core/UmpWriter.cpp) ---
    static void umpWriteVarInt(std::vector<uint8_t>& out, uint32_t value)
    {
        if (value < 128)
        {
            out.push_back(static_cast<uint8_t>(value));
        }
        else if (value < 16384)
        {
            out.push_back(static_cast<uint8_t>((value & 0x3F) | 0x80));
            out.push_back(static_cast<uint8_t>(value >> 6));
        }
        else if (value < 2097152)
        {
            out.push_back(static_cast<uint8_t>((value & 0x1F) | 0xC0));
            out.push_back(static_cast<uint8_t>((value >> 5) & 0xFF));
            out.push_back(static_cast<uint8_t>(value >> 13));
        }
        else if (value < 268435456)
        {
            out.push_back(static_cast<uint8_t>((value & 0x0F) | 0xE0));
            out.push_back(static_cast<uint8_t>((value >> 4) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 12) & 0xFF));
            out.push_back(static_cast<uint8_t>(value >> 20));
        }
        else
        {
            out.push_back(0xF0);
            uint32_t v = value;
            out.push_back(static_cast<uint8_t>(v & 0xFF));
            out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        }
    }

    static void umpWritePart(std::vector<uint8_t>& out, int partType, const std::vector<uint8_t>& partData)
    {
        const uint32_t partSize = static_cast<uint32_t>(partData.size());
        umpWriteVarInt(out, static_cast<uint32_t>(partType));
        umpWriteVarInt(out, partSize);
        out.insert(out.end(), partData.begin(), partData.end());
    }

    // Minimal protobuf decode for video_streaming.MediaHeader (we only need a few varint fields):
    // header_id (1), itag (3), is_init_seg (8), sequence_number (9)
    static bool parseMediaHeaderMeta(const CompositeBuffer& buf, uint8_t& headerIdOut, MediaHeaderMeta& metaOut)
    {
        const std::vector<uint8_t> bytes = compositeToVector(buf);
        size_t i = 0;
        bool hasHeader = false;
        uint32_t headerId32 = 0;

        while (i < bytes.size())
        {
            uint64_t tag;
            if (!pbReadVarint(bytes, i, tag)) break;
            const uint32_t field = (uint32_t)(tag >> 3);
            const uint32_t wt = (uint32_t)(tag & 0x07);

            if (field == 1 && wt == 0)
            {
                uint64_t v;
                if (!pbReadVarint(bytes, i, v)) return false;
                headerId32 = (uint32_t)v;
                hasHeader = true;
            }
            else if (field == 3 && wt == 0)
            {
                uint64_t v;
                if (!pbReadVarint(bytes, i, v)) return false;
                metaOut.hasItag = true;
                metaOut.itag = (int32_t)v;
            }
            else if (field == 8 && wt == 0)
            {
                uint64_t v;
                if (!pbReadVarint(bytes, i, v)) return false;
                metaOut.hasIsInitSeg = true;
                metaOut.isInitSeg = (v != 0);
            }
            else if (field == 9 && wt == 0)
            {
                uint64_t v;
                if (!pbReadVarint(bytes, i, v)) return false;
                metaOut.hasSeq = true;
                metaOut.sequenceNumber = (int32_t)v;
            }
            else
            {
                if (!pbSkipField(bytes, i, wt)) break;
            }
        }

        if (!hasHeader || headerId32 > 255)
            return false;

        headerIdOut = (uint8_t)headerId32;
        return true;
    }

    // Helper used only for UMP debugging: call ffmpeg.exe to extract the first frame as a PPM image.
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

    // Simple in-place overlay: draw a white box in the top-left corner of an RGB24 frame.
    static void drawSimpleOverlayRGB24(AVFrame* f)
    {
        if (!f || f->format != AV_PIX_FMT_RGB24 || !f->data[0])
            return;

        const int boxW = min(200, f->width);
        const int boxH = min(40, f->height);
        for (int y = 0; y < boxH; ++y)
        {
            uint8_t* row = f->data[0] + y * f->linesize[0];
            for (int x = 0; x < boxW; ++x)
            {
                row[x * 3 + 0] = 255; // B
                row[x * 3 + 1] = 255; // G
                row[x * 3 + 2] = 255; // R
            }
        }
    }

    struct MemBuffer
    {
        const uint8_t* data;
        size_t size;
        size_t pos;
    };

    static int readPacket(void* opaque, uint8_t* buf, int buf_size)
    {
        MemBuffer* mb = static_cast<MemBuffer*>(opaque);
        if (!mb || !mb->data)
            return AVERROR_EOF;
        size_t remaining = mb->size - mb->pos;
        int toCopy = static_cast<int>(min(remaining, static_cast<size_t>(buf_size)));
        if (toCopy <= 0)
            return AVERROR_EOF;
        memcpy(buf, mb->data + mb->pos, static_cast<size_t>(toCopy));
        mb->pos += static_cast<size_t>(toCopy);
        return toCopy;
    }

    struct OutBuffer
    {
        std::vector<uint8_t>* vec;
        int64_t pos;
    };

    // Write callback for custom AVIO that writes into a seekable in-memory vector.
    static int writePacket(void* opaque, const uint8_t* buf, int buf_size)
    {
        OutBuffer* ob = static_cast<OutBuffer*>(opaque);
        if (!ob || !ob->vec || !buf || buf_size <= 0)
            return AVERROR(EINVAL);

        std::vector<uint8_t>& v = *ob->vec;
        int64_t endPos = ob->pos + buf_size;
        if (endPos > static_cast<int64_t>(v.size()))
            v.resize(static_cast<size_t>(endPos));

        memcpy(v.data() + ob->pos, buf, static_cast<size_t>(buf_size));
        ob->pos = endPos;
        return buf_size;
    }

    // Seek callback to make the output AVIOContext seekable for the MP4 muxer.
    static int64_t seekPacket(void* opaque, int64_t offset, int whence)
    {
        OutBuffer* ob = static_cast<OutBuffer*>(opaque);
        if (!ob || !ob->vec)
            return AVERROR(EINVAL);

        std::vector<uint8_t>& v = *ob->vec;

        if (whence & AVSEEK_SIZE)
        {
            // Query for current buffer size.
            return static_cast<int64_t>(v.size());
        }

        int64_t newPos = 0;
        switch (whence)
        {
        case SEEK_SET:
            newPos = offset;
            break;
        case SEEK_CUR:
            newPos = ob->pos + offset;
            break;
        case SEEK_END:
            newPos = static_cast<int64_t>(v.size()) + offset;
            break;
        default:
            return AVERROR(EINVAL);
        }

        if (newPos < 0)
            return AVERROR(EINVAL);

        // Allow seeking past current end; buffer will grow on next write.
        ob->pos = newPos;
        return newPos;
    }

    // Decode an MP4 segment with FFmpeg libraries, draw a simple overlay on each video frame,
    // and re-encode back to MP4. This uses in-memory AVIO for both input and output, so no temp files.
    // In the UMP path we can feed init+fragment MP4 bytes here and get back a processed MP4.
    static bool processMp4WithFfmpegLibs(const std::vector<uint8_t>& inMp4,
                                         std::vector<uint8_t>& outMp4,
                                         const std::string& overlayText)
    {
        AVFormatContext* ifmtCtx = nullptr;
        AVFormatContext* ofmtCtx = nullptr;
        AVCodecContext* decCtx = nullptr;
        AVCodecContext* encCtx = nullptr;
        SwsContext* swsCtx = nullptr;
        AVFrame* frame = nullptr;
        AVFrame* rgbFrame = nullptr;
        AVPacket* pkt = nullptr;
        AVPacket* encPkt = nullptr;
        AVIOContext* inAvio = nullptr;
        AVIOContext* outAvio = nullptr;
        uint8_t* inAvioBuf = nullptr;
        uint8_t* outAvioBuf = nullptr;
        int videoStreamIndex = -1;
        bool ok = false;
        bool outputHeaderWritten = false;  // only call av_write_trailer if this is true
        MemBuffer mb{ inMp4.data(), inMp4.size(), 0 };
        OutBuffer ob{ &outMp4 };

        // ---------- Input: custom AVIO over in-memory MP4 ----------
        const int avioBufSize = 64 * 1024;
        inAvioBuf = static_cast<uint8_t*>(av_malloc(avioBufSize));
        if (!inAvioBuf)
            goto cleanup;

        ifmtCtx = avformat_alloc_context();
        if (!ifmtCtx)
            goto cleanup;
        inAvio = avio_alloc_context(
            inAvioBuf, avioBufSize,
            0,              // read-only
            &mb,
            &readPacket,
            nullptr,
            nullptr);
        if (!inAvio)
            goto cleanup;

        ifmtCtx->pb = inAvio;
        ifmtCtx->flags |= AVFMT_FLAG_CUSTOM_IO;

        if (avformat_open_input(&ifmtCtx, nullptr, nullptr, nullptr) < 0)
            goto cleanup;
        if (avformat_find_stream_info(ifmtCtx, nullptr) < 0)
            goto cleanup;

        // Find first video stream.
        for (unsigned int i = 0; i < ifmtCtx->nb_streams; ++i)
        {
            if (ifmtCtx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO)
            {
                videoStreamIndex = static_cast<int>(i);
                break;
            }
        }
        if (videoStreamIndex < 0)
            goto cleanup;

        {
            AVCodecParameters* codecpar = ifmtCtx->streams[videoStreamIndex]->codecpar;
            const AVCodec* dec = avcodec_find_decoder(codecpar->codec_id);
            if (!dec)
                goto cleanup;
            decCtx = avcodec_alloc_context3(dec);
            if (!decCtx)
                goto cleanup;
            if (avcodec_parameters_to_context(decCtx, codecpar) < 0)
                goto cleanup;
            if (avcodec_open2(decCtx, dec, nullptr) < 0)
                goto cleanup;
        }

        // ---------- Output: custom AVIO that writes into outMp4 ----------
        if (avformat_alloc_output_context2(&ofmtCtx, nullptr, "mp4", nullptr) < 0 || !ofmtCtx)
            goto cleanup;

        {
            const AVCodec* enc = avcodec_find_encoder(decCtx->codec_id);
            if (!enc)
                goto cleanup;
            AVStream* outStream = avformat_new_stream(ofmtCtx, enc);
            if (!outStream)
                goto cleanup;

            encCtx = avcodec_alloc_context3(enc);
            if (!encCtx)
                goto cleanup;

            encCtx->width = decCtx->width;
            encCtx->height = decCtx->height;

            // Choose a valid pixel format for the encoder without using deprecated AVCodec::pix_fmts.
            if (decCtx->pix_fmt != AV_PIX_FMT_NONE)
            {
                // Fall back to the decoder's pixel format if it's valid.
                encCtx->pix_fmt = decCtx->pix_fmt;
            }
            else
            {
                // As a last resort, use a common format.
                encCtx->pix_fmt = AV_PIX_FMT_YUV420P;
            }

            // Ensure the encoder has a valid, non-zero timebase and framerate.
            if (decCtx->framerate.num > 0 && decCtx->framerate.den > 0)
            {
                encCtx->time_base = av_inv_q(decCtx->framerate);
                encCtx->framerate = decCtx->framerate;
            }
            else if (decCtx->time_base.num > 0 && decCtx->time_base.den > 0)
            {
                encCtx->time_base = decCtx->time_base;
                encCtx->framerate = av_inv_q(decCtx->time_base);
            }
            else
            {
                // Fallback to a reasonable default if the decoder doesn't provide timing.
                encCtx->time_base = AVRational{ 1, 30 };
                encCtx->framerate = AVRational{ 30, 1 };
            }

            if (ofmtCtx->oformat->flags & AVFMT_GLOBALHEADER)
                encCtx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

            // Configure encoder options, especially for AV1/libaom, to avoid
            // excessive memory usage and make rate control explicit.
            {
                AVDictionary* opts = nullptr;

                if (enc->id == AV_CODEC_ID_AV1)
                {
                    // Use a constrained quality mode with an explicit CRF and
                    // disable some heavy features that can blow up memory usage.
                    av_dict_set(&opts, "usage", "realtime", 0);   // reduces lag buffers and complexity
                    av_dict_set(&opts, "lag-in-frames", "0", 0);  // avoid allocating large lag buffers
                    av_dict_set(&opts, "crf", "32", 0);           // explicit CRF
                    av_dict_set(&opts, "b", "0", 0);              // pure CRF (no bitrate)
                    av_dict_set(&opts, "enable-tpl", "0", 0);     // disable TPL model (saves RAM)
                    av_dict_set(&opts, "row-mt", "1", 0);         // row multi-threading
                    av_dict_set(&opts, "cpu-used", "7", 0);       // faster / lower memory

                    // Also give FFmpeg's generic RC fields a sane default bitrate
                    // so libaom does not fall back to its own heuristics.
                    encCtx->bit_rate = 1500000;                   // ~1.5 Mbps
                }

                int openErr = avcodec_open2(encCtx, enc, &opts);
                av_dict_free(&opts);
                if (openErr < 0)
                    goto cleanup;
            }

            if (avcodec_parameters_from_context(outStream->codecpar, encCtx) < 0)
                goto cleanup;
            outStream->time_base = encCtx->time_base;
        }

        outMp4.clear();
        {
            outAvioBuf = static_cast<uint8_t*>(av_malloc(avioBufSize));
            if (!outAvioBuf)
                goto cleanup;
            ob.pos = 0;
            outAvio = avio_alloc_context(
                outAvioBuf, avioBufSize,
                1,              // write
                &ob,
                nullptr,
                &writePacket,
                &seekPacket);
            if (!outAvio)
                goto cleanup;
            ofmtCtx->pb = outAvio;
            ofmtCtx->flags |= AVFMT_FLAG_CUSTOM_IO;
        }

        if (avformat_write_header(ofmtCtx, nullptr) < 0)
            goto cleanup;
        outputHeaderWritten = true;

        // Allocate frames.
        frame = av_frame_alloc();
        rgbFrame = av_frame_alloc();
        pkt = av_packet_alloc();
        encPkt = av_packet_alloc();
        if (!frame || !rgbFrame || !pkt || !encPkt)
            goto cleanup;

        while (av_read_frame(ifmtCtx, pkt) >= 0)
        {
            if (pkt->stream_index != videoStreamIndex)
            {
                av_packet_unref(pkt);
                continue;
            }

            if (avcodec_send_packet(decCtx, pkt) < 0)
            {
                av_packet_unref(pkt);
                goto cleanup;
            }
            av_packet_unref(pkt);

            while (true)
            {
                int ret = avcodec_receive_frame(decCtx, frame);
                if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
                    break;
                if (ret < 0)
                    goto cleanup;

                // Convert to RGB24 for a simple overlay, then back to encoder pixel format.
                swsCtx = sws_getCachedContext(
                    swsCtx,
                    frame->width, frame->height, static_cast<AVPixelFormat>(frame->format),
                    frame->width, frame->height, AV_PIX_FMT_RGB24,
                    SWS_BILINEAR, nullptr, nullptr, nullptr);
                if (!swsCtx)
                    goto cleanup;

                if (!rgbFrame->data[0])
                {
                    if (av_image_alloc(rgbFrame->data, rgbFrame->linesize,
                        frame->width, frame->height, AV_PIX_FMT_RGB24, 1) < 0)
                        goto cleanup;
                }

                sws_scale(swsCtx,
                    frame->data, frame->linesize,
                    0, frame->height,
                    rgbFrame->data, rgbFrame->linesize);

                drawSimpleOverlayRGB24(rgbFrame);

                // Convert back to encoder pixel format.
                SwsContext* swsBack = sws_getCachedContext(
                    nullptr,
                    frame->width, frame->height, AV_PIX_FMT_RGB24,
                    frame->width, frame->height, encCtx->pix_fmt,
                    SWS_BILINEAR, nullptr, nullptr, nullptr);
                if (!swsBack)
                    goto cleanup;

                AVFrame* encFrame = av_frame_alloc();
                if (!encFrame)
                {
                    sws_freeContext(swsBack);
                    goto cleanup;
                }
                encFrame->format = encCtx->pix_fmt;
                encFrame->width = frame->width;
                encFrame->height = frame->height;
                if (av_frame_get_buffer(encFrame, 32) < 0)
                {
                    av_frame_free(&encFrame);
                    sws_freeContext(swsBack);
                    goto cleanup;
                }

                sws_scale(swsBack,
                    rgbFrame->data, rgbFrame->linesize,
                    0, frame->height,
                    encFrame->data, encFrame->linesize);
                sws_freeContext(swsBack);

                encFrame->pts = frame->pts;

                if (avcodec_send_frame(encCtx, encFrame) < 0)
                {
                    av_frame_free(&encFrame);
                    goto cleanup;
                }
                av_frame_free(&encFrame);

                while (true)
                {
                    int er = avcodec_receive_packet(encCtx, encPkt);
                    if (er == AVERROR(EAGAIN) || er == AVERROR_EOF)
                        break;
                    if (er < 0)
                        goto cleanup;

                    encPkt->stream_index = 0;
                    av_packet_rescale_ts(encPkt, decCtx->time_base, ofmtCtx->streams[0]->time_base);
                    if (av_interleaved_write_frame(ofmtCtx, encPkt) < 0)
                    {
                        av_packet_unref(encPkt);
                        goto cleanup;
                    }
                    av_packet_unref(encPkt);
                }
            }
        }

        // Flush encoder.
        avcodec_send_frame(encCtx, nullptr);
        while (true)
        {
            int er = avcodec_receive_packet(encCtx, encPkt);
            if (er == AVERROR(EAGAIN) || er == AVERROR_EOF)
                break;
            if (er < 0)
                goto cleanup;
            encPkt->stream_index = 0;
            av_packet_rescale_ts(encPkt, decCtx->time_base, ofmtCtx->streams[0]->time_base);
            if (av_interleaved_write_frame(ofmtCtx, encPkt) < 0)
            {
                av_packet_unref(encPkt);
                goto cleanup;
            }
            av_packet_unref(encPkt);
        }

        ok = true;
        // av_write_trailer is called once in cleanup (only when outputHeaderWritten), not here, to avoid double call

    cleanup:
        if (pkt) av_packet_free(&pkt);
        if (encPkt) av_packet_free(&encPkt);
        if (frame) av_frame_free(&frame);
        if (rgbFrame)
        {
            if (rgbFrame->data[0])
                av_freep(&rgbFrame->data[0]);
            av_frame_free(&rgbFrame);
        }
        if (swsCtx) sws_freeContext(swsCtx);
        if (decCtx) avcodec_free_context(&decCtx);
        if (encCtx) avcodec_free_context(&encCtx);
        if (ifmtCtx) avformat_close_input(&ifmtCtx);
        if (ifmtCtx)
        {
            // avformat_close_input frees the context and its pb; do not free pb again
            avformat_close_input(&ifmtCtx);
        }
        if (ofmtCtx)
        {
            AVIOContext* tmp = ofmtCtx->pb;
            if (outputHeaderWritten)
            {
                if (av_write_trailer(ofmtCtx) < 0)
                    ok = false;  // trailer write failed; output may be incomplete
            }
            ofmtCtx->pb = nullptr;  // we own pb for muxing; free it ourselves so avformat_free_context doesn't touch it
            avformat_free_context(ofmtCtx);
            if (tmp)
            {
                avio_context_free(&tmp);  // frees context; buffer may have been replaced by libavformat (e.g. if >32KB), so don't touch tmp->buffer
            }
            if (outAvioBuf)
            {
                av_freep(&outAvioBuf);  // our allocation from avio_alloc_context
            }
        }
        return ok;
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
        // Part IDs (from YouTube UMP): MEDIA_HEADER=20, MEDIA=21, MEDIA_END=22
        const int UMP_PART_ID_MEDIA_HEADER = 20;
        const int UMP_PART_ID_MEDIA = 21;
        const int UMP_PART_ID_MEDIA_END = 22;

        if (part.type == UMP_PART_ID_MEDIA_HEADER)
        {
            uint8_t hdr = 0;
            MediaHeaderMeta meta;
            if (parseMediaHeaderMeta(part.data, hdr, meta))
            {
                // Merge into existing meta (keep any already-known fields if new parse didn't include them)
                MediaHeaderMeta& cur = assem.metaByHeaderId[hdr];
                if (meta.hasIsInitSeg) { cur.hasIsInitSeg = true; cur.isInitSeg = meta.isInitSeg; }
                if (meta.hasItag) { cur.hasItag = true; cur.itag = meta.itag; }
                if (meta.hasSeq) { cur.hasSeq = true; cur.sequenceNumber = meta.sequenceNumber; }

                printf("[UMP] MediaHeader headerId=%u itag=%s is_init_seg=%s seq=%s\n",
                    (unsigned)hdr,
                    cur.hasItag ? std::to_string(cur.itag).c_str() : "?",
                    cur.hasIsInitSeg ? (cur.isInitSeg ? "true" : "false") : "?",
                    cur.hasSeq ? std::to_string(cur.sequenceNumber).c_str() : "?");

                // Re-emit the MEDIA_HEADER part into the rewritten UMP stream unchanged.
                const std::vector<uint8_t> headerBytes = compositeToVector(part.data);
                umpWritePart(assem.rewrittenUmpOut, UMP_PART_ID_MEDIA_HEADER, headerBytes);
            }
            return;
        }
        else if (part.type == UMP_PART_ID_MEDIA)
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

            const auto itMeta = assem.metaByHeaderId.find(headerId);
            const bool metaSaysInit = (itMeta != assem.metaByHeaderId.end() && itMeta->second.hasIsInitSeg && itMeta->second.isInitSeg);
            const bool heuristicInit = looksLikeInitSegment(segment);
            const bool isInit = metaSaysInit || heuristicInit;

            if (isInit)
            {
                assem.initByHeaderId[headerId] = std::move(segment);
                if (itMeta != assem.metaByHeaderId.end() && itMeta->second.hasItag)
                {
                    assem.initByItag[itMeta->second.itag] = assem.initByHeaderId[headerId];
                }
                printf("[UMP] Stored init segment for headerId=%u (%zu bytes)\n",
                    (unsigned)headerId, assem.initByHeaderId[headerId].size());

                // If we previously queued fragments waiting for init, replay them now.
                auto itPending = assem.pendingByHeaderId.find(headerId);
                if (itPending != assem.pendingByHeaderId.end() && !itPending->second.empty())
                {
                    printf("[UMP] Replaying %zu pending fragment(s) for headerId=%u now that init is available\n",
                        itPending->second.size(), (unsigned)headerId);

                    // Move pending out to avoid re-entrancy issues.
                    auto pending = std::move(itPending->second);
                    assem.pendingByHeaderId.erase(itPending);

                    for (auto& frag : pending)
                    {
                        // Re-run MEDIA_END logic path by setting segment=frag (local copy) below.
                        // We'll just inline the processing for simplicity.
                        auto itInit2 = assem.initByHeaderId.find(headerId);
                        if (itInit2 == assem.initByHeaderId.end() || itInit2->second.empty())
                            break;

                        std::vector<uint8_t> mp4;
                        mp4.reserve(itInit2->second.size() + frag.size());
                        mp4.insert(mp4.end(), itInit2->second.begin(), itInit2->second.end());
                        mp4.insert(mp4.end(), frag.begin(), frag.end());

                        std::vector<uint8_t> processedMp4;
                        if (processMp4WithFfmpegLibs(mp4, processedMp4, g_overlayText))
                        {
                            printf("[UMP] Processed replayed UMP segment for headerId=%u (%zu -> %zu bytes)\n",
                                (unsigned)headerId, mp4.size(), processedMp4.size());
                        }
                        else
                        {
                            printf("[UMP] FFmpeg library processing failed (replayed) for headerId=%u\n",
                                (unsigned)headerId);
                        }
                    }
                }
                return;
            }

            // Find init by headerId first; if missing, try by itag (sometimes header ids change across init/media).
            const std::vector<uint8_t>* init = nullptr;
            auto itInit = assem.initByHeaderId.find(headerId);
            if (itInit != assem.initByHeaderId.end() && !itInit->second.empty())
                init = &itInit->second;

            if (!init && itMeta != assem.metaByHeaderId.end() && itMeta->second.hasItag)
            {
                auto itInitItag = assem.initByItag.find(itMeta->second.itag);
                if (itInitItag != assem.initByItag.end() && !itInitItag->second.empty())
                    init = &itInitItag->second;
            }

            if (!init)
            {
                auto& q = assem.pendingByHeaderId[headerId];
                const size_t segSize = segment.size();
                if (q.size() < 6) // simple cap to avoid unbounded memory growth
                    q.push_back(std::move(segment));

                printf("[UMP] No init segment yet for headerId=%u, queued media fragment (%zu bytes). pending=%zu\n",
                    (unsigned)headerId, segSize, q.size());
                return;
            }

            // Combine init + fragment and process with FFmpeg libraries.
            std::vector<uint8_t> mp4;
            mp4.reserve(init->size() + segment.size());
            mp4.insert(mp4.end(), init->begin(), init->end());
            mp4.insert(mp4.end(), segment.begin(), segment.end());

            std::vector<uint8_t> processedMp4;
            bool processedOk = processMp4WithFfmpegLibs(mp4, processedMp4, g_overlayText);
            if (processedOk)
            {
                printf("[UMP] Processed UMP segment for headerId=%u (%zu -> %zu bytes)\n",
                    (unsigned)headerId, mp4.size(), processedMp4.size());
            }
            else
            {
                printf("[UMP] FFmpeg library processing failed for headerId=%u, falling back to original bytes\n",
                    (unsigned)headerId);
                processedMp4 = std::move(mp4);
            }

            // Repackage the (possibly processed) MP4 back into UMP MEDIA + MEDIA_END
            // parts so it can be delivered back to the browser. For simplicity we
            // emit a single MEDIA part containing the full fragment, followed by a
            // MEDIA_END containing only the headerId, which matches the example
            // shape in googlevideo-c/tests/ump_example_test.cpp.
            std::vector<uint8_t> mediaData;
            mediaData.reserve(1 + processedMp4.size());
            mediaData.push_back(headerId);
            mediaData.insert(mediaData.end(), processedMp4.begin(), processedMp4.end());
            umpWritePart(assem.rewrittenUmpOut, UMP_PART_ID_MEDIA, mediaData);

            std::vector<uint8_t> mediaEndData(1);
            mediaEndData[0] = headerId;
            umpWritePart(assem.rewrittenUmpOut, UMP_PART_ID_MEDIA_END, mediaEndData);
        }
    }

    // Legacy path for non-UMP streams: still available as a fallback which uses the ffmpeg.exe CLI.
    // New codepaths should prefer processMp4WithFfmpegLibs.
    bool processVideoWithFFmpeg(const char* inputData, size_t inputSize,
        std::vector<char>& outputData)
    {
        std::vector<uint8_t> inMp4(inputData, inputData + inputSize);
        std::vector<uint8_t> outMp4;
        if (!processMp4WithFfmpegLibs(inMp4, outMp4, g_overlayText))
        {
            printf("FFmpeg library processing failed\n");
            return false;
        }
        outputData.assign(outMp4.begin(), outMp4.end());
        return true;
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

                        // Before consuming parts, remember how many rewritten bytes we have already
                        // emitted so we can compute the delta for this chunk.
                        const size_t prevRewrittenSize = assem.rewrittenUmpOut.size();

                        consumeUmpParts(assem, [&](const UmpPart& part) { handleUmpPart(assem, part); });

                        // After processing, any new bytes appended to rewrittenUmpOut correspond
                        // to this chunk of input. Replace the HTTP body with those bytes so the
                        // browser sees the modified UMP stream instead of the original one.
                        if (assem.rewrittenUmpOut.size() > prevRewrittenSize)
                        {
                            size_t available = assem.rewrittenUmpOut.size() - assem.rewrittenSentOffset;
                            if (available > 0)
                            {
                                pStream->reset();
                                pStream->write(
                                    reinterpret_cast<const char*>(assem.rewrittenUmpOut.data() + assem.rewrittenSentOffset),
                                    (tStreamSize)available);
                                assem.rewrittenSentOffset = assem.rewrittenUmpOut.size();
                            }
                        }
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
