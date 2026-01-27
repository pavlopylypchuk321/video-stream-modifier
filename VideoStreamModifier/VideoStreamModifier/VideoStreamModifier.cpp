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
#include <process.h>

#include "ProtocolFilters.h"
#include "PFEventsDefault.h"

#include "samples_config.h"

#pragma comment(lib, "ws2_32.lib")

using namespace nfapi;
using namespace ProtocolFilters;

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
        inputFile += ".mp4";
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

                    if (isYouTubeVideoURL(url))
                        printf("[HTTP/1.1] YouTube request: %s\n", url.c_str());
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
                
                if (isYouTube || isVideo)
                {
                    PFStream* cs = object->getStream(contentIndex);
                    printf("[dataAvailable] *** Video Response - URL: %s, Content-Type: %s, Size: %llu\n", 
                           url.empty() ? "(empty)" : url.c_str(),
                           pContentTypeField ? pContentTypeField->value().c_str() : "(none)",
                           cs ? (unsigned long long)cs->size() : 0);
                }
                
                if (pContentTypeField && isYouTube && isVideo)
                {
                    // Check if this is video content
                    PFStream* pStream = object->getStream(contentIndex);
                    if (pStream && pStream->size() > 0)
                    {
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
