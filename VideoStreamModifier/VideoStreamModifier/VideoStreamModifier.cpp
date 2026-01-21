// Adds a prefix to the titles of HTML pages.
//

#include <crtdbg.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
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

// Structure to track video stream buffers per connection
struct VideoStreamBuffer {
    std::vector<char> data;
    std::string contentType;
    std::string url;
    bool isVideoStream;
    
    VideoStreamBuffer() : isVideoStream(false) {}
};

class HttpFilter : public PFEventsDefault
{
private:
    std::map<nfapi::ENDPOINT_ID, VideoStreamBuffer> m_videoBuffers;

    bool isVideoContentType(const std::string& contentType)
    {
        if (contentType.find("video/") != std::string::npos)
            return true;
        if (contentType.find("application/vnd.apple.mpegurl") != std::string::npos)  // HLS
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

    std::string getURLFromHeader(PFObject* object)
    {
        PFHeader h;
        if (pf_readHeader(object->getStream(HS_HEADER), &h))
        {
            // Try to get host and path
            std::string host, path;
            
            PFHeaderField* pHostField = h.findFirstField("Host");
            if (pHostField)
                host = pHostField->value();
            
            PFHeaderField* pPathField = h.findFirstField(":path");
            if (pPathField)
                path = pPathField->value();
            else
            {
                pPathField = h.findFirstField("Request-URI");
                if (pPathField)
                    path = pPathField->value();
            }
            
            if (!host.empty() && !path.empty())
                return host + path;
            else if (!path.empty())
                return path;
        }
        return "";
    }

    bool processVideoWithFFmpeg(const char* inputData, size_t inputSize, 
                                 std::vector<char>& outputData)
    {
        // Create temporary input file
        char tempInputPath[MAX_PATH];
        char tempOutputPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempInputPath);
        GetTempFileNameA(tempInputPath, "vid", 0, tempInputPath);
        GetTempFileNameA(tempInputPath, "vid", 0, tempOutputPath);
        
        // Change extension
        std::string inputFile = tempInputPath;
        std::string outputFile = tempOutputPath;
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

    virtual void tcpDisconnected(nfapi::ENDPOINT_ID id)
    {
        // Clean up buffer when connection closes
        m_videoBuffers.erase(id);
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
        if (object->isReadOnly())
            return;

        if ((object->getType() == OT_HTTP_RESPONSE) ||
            (object->getType() == OT_HTTP2_RESPONSE))
        {
            PFHeader h;

            if (pf_readHeader(object->getStream(HS_HEADER), &h))
            {
                PFHeaderField* pField = h.findFirstField("Content-Type");
                if (pField)
                {
                    std::string contentType = pField->value();
                    
                    // Check if this is video content
                    if (isVideoContentType(contentType))
                    {
                        std::string url = getURLFromHeader(object);
                        
                        // Check if it's YouTube video
                        if (isYouTubeVideoURL(url))
                        {
                            PFStream* pStream = object->getStream(HS_CONTENT);
                            if (pStream && pStream->size() > 0)
                            {
                                // Read the entire video segment/chunk
                                size_t chunkSize = (size_t)pStream->size();
                                
                                // Only process if we have a reasonable amount of data
                                // (too small might be metadata or headers)
                                if (chunkSize > 10240)  // At least 10KB
                                {
                                    printf("Processing YouTube video segment: %zu bytes from %s\n", 
                                           chunkSize, url.c_str());
                                    
                                    // Read video data
                                    std::vector<char> videoData(chunkSize);
                                    pStream->read(videoData.data(), (tStreamSize)chunkSize);
                                    
                                    // Process video with FFmpeg
                                    std::vector<char> processedData;
                                    if (processVideoWithFFmpeg(videoData.data(), videoData.size(), processedData))
                                    {
                                        // Replace content with processed video
                                        pStream->reset();
                                        pStream->write(processedData.data(), (tStreamSize)processedData.size());
                                        
                                        printf("Video processed: %zu -> %zu bytes\n", 
                                               videoData.size(), processedData.size());
                                    }
                                    else
                                    {
                                        // FFmpeg failed, restore original data
                                        pStream->reset();
                                        pStream->write(videoData.data(), (tStreamSize)videoData.size());
                                        printf("FFmpeg processing failed, using original video\n");
                                    }
                                }
                                else
                                {
                                    // Small chunk, likely metadata - pass through
                                    printf("Skipping small video chunk: %zu bytes\n", chunkSize);
                                }
                            }
                        }
                    }
                }
            }
        }

        pf_postObject(id, object);
    }

    PF_DATA_PART_CHECK_RESULT
        dataPartAvailable(nfapi::ENDPOINT_ID id, PFObject* object)
    {
        if (object->getType() == OT_SSL_HANDSHAKE_OUTGOING)
        {
            PFStream* pStream = object->getStream(0);
            char* buf;
            PF_DATA_PART_CHECK_RESULT res = DPCR_FILTER;

            if (pStream && pStream->size() > 0)
            {
                buf = (char*)malloc((size_t)pStream->size() + 1);
                if (buf)
                {
                    pStream->read(buf, (tStreamSize)pStream->size());
                    buf[pStream->size()] = '\0';

                    if (strcmp(buf, "get.adobe.com") == 0)
                    {
                        res = DPCR_BYPASS;
                    }

                    free(buf);
                }
            }
            return res;
        }

        if (object->getType() == OT_HTTP_RESPONSE ||
            object->getType() == OT_HTTP2_RESPONSE)
        {
            PFHeader h;

            if (pf_readHeader(object->getStream(HS_HEADER), &h))
            {
                PFHeaderField* pField = h.findFirstField("Content-Type");
                if (pField)
                {
                    std::string contentType = pField->value();
                    
                    // Check if this is video content
                    if (isVideoContentType(contentType))
                    {
                        std::string url = getURLFromHeader(object);
                        
                        // Check if it's YouTube video
                        if (isYouTubeVideoURL(url))
                        {
                            PFStream* pStream = object->getStream(HS_CONTENT);
                            if (pStream && pStream->size() > 10240)  // Only process substantial chunks
                            {
                                // Read video data
                                size_t chunkSize = (size_t)pStream->size();
                                std::vector<char> videoData(chunkSize);
                                pStream->read(videoData.data(), (tStreamSize)chunkSize);
                                
                                // Process video with FFmpeg
                                std::vector<char> processedData;
                                if (processVideoWithFFmpeg(videoData.data(), videoData.size(), processedData))
                                {
                                    // Replace content with processed video
                                    pStream->reset();
                                    pStream->write(processedData.data(), (tStreamSize)processedData.size());
                                    return DPCR_UPDATE_AND_BYPASS;
                                }
                                else
                                {
                                    // Restore original and bypass
                                    pStream->reset();
                                    pStream->write(videoData.data(), (tStreamSize)videoData.size());
                                    return DPCR_BYPASS;
                                }
                            }
                            else
                            {
                                // Need more data for video processing
                                return DPCR_MORE_DATA_REQUIRED;
                            }
                        }
                    }
                }
            }
        }

        return DPCR_BYPASS;
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
