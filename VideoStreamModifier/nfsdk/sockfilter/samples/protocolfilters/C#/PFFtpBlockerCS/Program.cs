using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using pfapinet;
using nfapinet;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.IO;

namespace PFFtpBlockerCS
{
    using ENDPOINT_ID = Int64;

    class Filter : PFEventsDefault
    {
        private byte[] m_blockString;
        private UInt64 m_maxFileSize = 100 * 1024 * 1024;

	    class FTP_DATA_INFO
	    {
            public PFObject buffer;
            public bool filteringDisabled;
	    };

        private Dictionary<ulong, FTP_DATA_INFO> m_dataInfoMap = new Dictionary<ulong,FTP_DATA_INFO>();

	    class FTP_CMD_INFO
	    {
		    public List<string> requests;
            public List<string> pendedRequests;

            public int nWaitingResponses;
            public bool filterCmdData;
	    };

	    Dictionary<ulong, FTP_CMD_INFO> m_cmdInfoMap = new Dictionary<ulong,FTP_CMD_INFO>();

        public void setBlockString(string s)
        {
            m_blockString = convertToByteArray(s.ToCharArray());
        }

        public unsafe byte[] loadBuffer(PFStream pStream, bool seekToBegin)
        {
            if (pStream == null || pStream.size() == 0)
                return null;

            byte[] buf = new byte[pStream.size()];

            if (seekToBegin)
            {
                pStream.seek(0, (int)SeekOrigin.Begin);
            }

            fixed (byte* p = buf)
            {
                pStream.read((IntPtr)p, (uint)pStream.size());
                return buf;
            }
        }

        unsafe bool saveBuffer(PFStream pStream, byte[] buf, bool clearStream)
        {
            if (pStream == null)
                return false;

            if (clearStream)
            {
                pStream.reset();
            }

            fixed (byte* p = buf)
            {
                if (pStream.write((IntPtr)p, (uint)buf.Length) < buf.Length)
                    return false;
            }
            return true;
        }

        unsafe bool appendStreamContent(PFStream streamFrom, PFStream streamTo)
        {
	        byte[] tempBuf = new byte[1000];
	        UInt64 nBytes;

            streamTo.seek(0, (int)SeekOrigin.Begin);
            streamFrom.seek(0, (int)SeekOrigin.Begin);

            fixed (byte* p = tempBuf)
            {
	            for (;;)
	            {
		            nBytes = streamFrom.read((IntPtr)p, (uint)tempBuf.Length);
		            if (nBytes == 0)
			            break;

		            if (streamTo.write((IntPtr)p, (uint)nBytes) != nBytes)
			            return false;
	            }
            }

	        return true;
        }

        private void _splitString(string s, 
				         ref string[] parts, 
				         char[] dividers)
        {
            parts = s.Split(dividers);
        }

        private byte[] convertToByteArray(char[] chars)
        {
            if (chars == null ||
                chars.Length == 0)
            {
                return null;
            }

            byte[] bytes = new byte[chars.Length];

            for (int i=0; i<chars.Length; i++)
            {
                bytes[i] = (byte)chars[i];
            }

            return bytes;
        }

        private string convertToString(byte[] bytes)
        {
            if (bytes == null ||
                bytes.Length == 0)
            {
                return null;
            }

            char[] chars = new char[bytes.Length];

            for (int i = 0; i < bytes.Length; i++)
            {
                chars[i] = (char)bytes[i];
            }

            return new string(chars);
        }

        private PFObject createObject(pfapinet.PF_ObjectType type, int nStreams, byte[] content)
        {
	        PFObject obj = pfapinet.PFObject.create(type, nStreams);
        	
	        if (content.Length > 0)
	        {
                saveBuffer(obj.getStream(0), content, false);
	        }
        	
	        return obj;
        }

        private bool postCmdData(ulong id, PF_ObjectType type, string content)
        {
	        if (type == pfapinet.PF_ObjectType.OT_FTP_COMMAND)
	        {
		        Console.Out.WriteLine("Post request: {0}", content);
	        } else
	        {
		        Console.Out.WriteLine("Post response: {0}", content);
	        }

	        string data = content + "\n";

            PFObject obj = createObject(type, 2, convertToByteArray(data.ToCharArray()));
        	
	        PFAPI.pf_postObject(id, ref obj);
        	
	        obj.free();

	        return true;
        }

        private bool compareBuffers(byte[] buf1, int offset, byte[] buf2)
        {
            for (int i = 0; i < buf2.Length; i++)
            {
                if (buf1[offset + i] != buf2[i])
                    return false;
            }
            return true;
        }

        private bool bufferContans(byte[] buf, byte[] subBuf)
        {
	        for (int i = 0; i < buf.Length - subBuf.Length; i++)
	        {
                if (compareBuffers(buf, i, subBuf))
			        return true;
	        }

	        return false;
        }

        private bool bufferMustBeBlocked(PFObject obj)
        {
            byte[] content = loadBuffer(obj.getStream(0), true);

            return bufferContans(content, m_blockString);
        }

        private struct FTPObjectInfo
        {
            public string command;
            public string fileName;
            public ulong sessionId;
        }

        private bool getObjectInfo(PFObject obj, ref FTPObjectInfo objectInfo)
        {
	        pfapinet.PFHeader h;

	        h = PFAPI.pf_readHeader(obj.getStream(1));

	        string cmd;

	        cmd = h["COMMAND"];
	        if (cmd != null)
	        {
		        objectInfo.command = cmd;

		        int pos = cmd.IndexOf(' ');
		        if (pos != -1)
		        {
			        objectInfo.fileName = cmd.Substring(pos+1);
		        }
	        }

	        cmd = h["SESSIONID"];
	        if (cmd != null)
	        {
		        objectInfo.sessionId = Convert.ToUInt64(cmd);
	        }
         
	        return true;
        }


        public override void tcpConnected(ulong id, NF_TCP_CONN_INFO pConnInfo)
        {
            PFAPI.pf_addFilter(id,
                PF_FilterType.FT_PROXY,
                PF_FilterFlags.FF_READ_ONLY_IN | PF_FilterFlags.FF_READ_ONLY_OUT,
                PF_OpTarget.OT_LAST,
                PF_FilterType.FT_NONE);

            PFAPI.pf_addFilter(id,
                PF_FilterType.FT_SSL,
                PF_FilterFlags.FF_SSL_INDICATE_HANDSHAKE_REQUESTS,
                PF_OpTarget.OT_LAST,
                PF_FilterType.FT_NONE);

            PFAPI.pf_addFilter(id,
                PF_FilterType.FT_FTP,
                PF_FilterFlags.FF_DEFAULT,
                PF_OpTarget.OT_LAST,
                PF_FilterType.FT_NONE);
        }


        public override void dataAvailable(ulong id, ref PFObject pObject)
        {
	        FTP_CMD_INFO pci;

            if (pObject.isReadOnly())
                return;

	        if (pObject.getType() == pfapinet.PF_ObjectType.OT_FTP_COMMAND)
	        {
                try
                {
                    pci = m_cmdInfoMap[id];
                }
                catch (Exception)
                {
                    pci = null;
                }

		        if (pci == null)
		        {
			        pci = new FTP_CMD_INFO();
			        
                    pci.nWaitingResponses = 0;
			        pci.filterCmdData = false;
			        pci.requests = new List<string>();
			        pci.pendedRequests = new List<string>();

    			    m_cmdInfoMap[id] = pci;
		        }

		        byte[] content = loadBuffer(pObject.getStream(0), true);
		        
                if (content == null)
                {
			        PFAPI.pf_postObject(id, ref pObject);
			        return;
		        }

                string strContent = convertToString(content);

                string[] parts = strContent.Split("\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);

		        for (int i=0; i<parts.Length; i++)
		        {
			        if (pci.requests.Count > 0)
			        {
				        Console.Out.WriteLine("pended request {0}", parts[i]);
				        pci.pendedRequests.Add(parts[i]);
			        } else
			        {
				        Console.Out.WriteLine("request {0}", parts[i]);
                        postCmdData(id, pfapinet.PF_ObjectType.OT_FTP_COMMAND, parts[i]);
			        }
		        }

		        return;
	        } else
	        if (pObject.getType() == pfapinet.PF_ObjectType.OT_FTP_RESPONSE)
	        {
                try
                {
                    pci = m_cmdInfoMap[id];
                }
                catch (Exception)
                {
                    pci = null;
                }

		        if (pci != null)
		        {
                    byte[] content = loadBuffer(pObject.getStream(0), true);

                    if (content == null)
			        {
                        PFAPI.pf_postObject(id, ref pObject);
				        return;
			        }

                    string strContent = convertToString(content);

                    string[] parts = strContent.Split("\n".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);

			        for (int i=0; i<parts.Length; i++)
			        {
				        Console.Out.WriteLine("response {0}", parts[i]);

				        Console.Out.WriteLine("nWaitingResponses = {0}\n", pci.nWaitingResponses);

				        if (parts[i].StartsWith("150"))
				        {
					        postCmdData(id, pfapinet.PF_ObjectType.OT_FTP_RESPONSE, parts[i]);
					        continue;
				        } 
    					
				        if (pci.requests.Count == 0)
				        {
					        postCmdData(id, pfapinet.PF_ObjectType.OT_FTP_RESPONSE, parts[i]);
					        continue;
				        }

				        if (pci.nWaitingResponses > 0)
				        {
					        pci.nWaitingResponses--;

					        postCmdData(id, pfapinet.PF_ObjectType.OT_FTP_RESPONSE, parts[i]);
				        } else
				        if (pci.requests.Count > 0)
				        {
					        pci.requests.RemoveAt(0);
				        }
			        }

			        if (pci.nWaitingResponses == 0)
			        {
				        if (pci.requests.Count > 0)
				        {
					        string s = pci.requests[0];
					        postCmdData(id, pfapinet.PF_ObjectType.OT_FTP_COMMAND, s);
				        } else
				        if (pci.pendedRequests.Count > 0)
				        {
					        string s = pci.pendedRequests[0];

					        postCmdData(id, pfapinet.PF_ObjectType.OT_FTP_COMMAND, s);

					        pci.pendedRequests.RemoveAt(0);
					        pci.nWaitingResponses++;
				        }
			        }

			        return;
		        }

	        }

	        if (pObject.getType() == pfapinet.PF_ObjectType.OT_TCP_DISCONNECT_LOCAL)
	        {
		        FTP_DATA_INFO di;

                try
                {
                    di = m_dataInfoMap[id];
                } catch(Exception )
                {
                    di = null;
                }

                if (di != null)
		        {
			        if (di.filteringDisabled)
			        {
				        di.buffer.free();
				        m_dataInfoMap.Remove(id);
                        PFAPI.pf_postObject(id, ref pObject);
				        return;
			        }

			        if (bufferMustBeBlocked(di.buffer))
			        {
				        FTPObjectInfo objectInfo = new FTPObjectInfo();

				        if (getObjectInfo(di.buffer, ref objectInfo))
				        {
					        Console.Out.WriteLine("Blocked file name: {0}", objectInfo.fileName);
					        Console.Out.WriteLine("Command session id: {0}", objectInfo.sessionId);

					        pci = m_cmdInfoMap[objectInfo.sessionId];

					        if (pci != null)
					        {
						        pci.requests.Add("DELE "+objectInfo.fileName+"\r");
						        pci.nWaitingResponses = 1;
					        }
				        }

				        di.buffer.free();
				        m_dataInfoMap.Remove(id);

                        PFAPI.pf_postObject(id, ref pObject);
				        return;
			        } else
			        {
                        PFAPI.pf_postObject(id, ref di.buffer);
			        }

			        di.buffer.free();
			        m_dataInfoMap.Remove(id);
		        }

                PFAPI.pf_postObject(id, ref pObject);
		        return;
	        } 

	        if (pObject.getType() == pfapinet.PF_ObjectType.OT_FTP_DATA_PART_OUTGOING)
	        {
		        FTP_DATA_INFO di;
                
                try
                {
                    di = m_dataInfoMap[id];
                }
                catch (Exception)
                {
                    di = null;
                }

		        if (di == null)
		        {
                    di = new FTP_DATA_INFO();

			        di.buffer = pfapinet.PFObject.create(pfapinet.PF_ObjectType.OT_FTP_DATA_PART_OUTGOING, 2);
			        if (di.buffer == null)
			        {
                        PFAPI.pf_postObject(id, ref pObject);
				        return;
			        }

			        if (m_maxFileSize == 0)
				        di.buffer.setReadOnly(true);

                    PFStream pStream = di.buffer.getStream(1);
			        pObject.getStream(1).copyTo(ref pStream);

			        FTPObjectInfo objectInfo = new FTPObjectInfo();

			        if (getObjectInfo(di.buffer, ref objectInfo))
			        {
				        Console.Out.WriteLine("File name: {0}", objectInfo.fileName);
				        Console.Out.WriteLine("Command session id: {0}", objectInfo.sessionId);
			        }

			        di.filteringDisabled = false;

			        m_dataInfoMap[id] = di;
		        }

		        if (!di.filteringDisabled)
		        {
			        PFStream bufferStream = di.buffer.getStream(0);
			        PFStream objectStream = pObject.getStream(0);

			        if (!appendStreamContent(objectStream, bufferStream))
			        {
                        PFAPI.pf_postObject(id, ref pObject);
				        return;
			        }

			        if (m_maxFileSize > 0)
			        {
				        if (bufferStream.size() > m_maxFileSize)
				        {
                            Console.Out.WriteLine("File is too large, bypass");

                            PFAPI.pf_postObject(id, ref di.buffer);

					        di.filteringDisabled = true;
					        m_dataInfoMap[id] = di;
				        }
    				
				        return;
			        }
		        }
	        } 


            PFAPI.pf_postObject(id, ref pObject);
        }

        public override PF_DATA_PART_CHECK_RESULT dataPartAvailable(ulong id, ref PFObject pObject)
        {
            return PF_DATA_PART_CHECK_RESULT.DPCR_BYPASS;
        }
    }

    class Program
    {
        static Filter m_filter = new Filter();

        static void usage()
        {
            Console.Out.WriteLine("Usage: PFFtpBlockerCS.exe <string>");
            Console.Out.WriteLine("<string> : block the uploaded files with this string in content");
        }

        unsafe static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                usage();
                return;
            }

            m_filter.setBlockString(args[0]);

            if (!PFAPI.pf_init(m_filter, "c:\\netfilter2"))
                return;

            PFAPI.pf_setRootSSLCertSubject("NFSDK Sample CA");

            if (NFAPI.nf_init(nfapinet.samples_config.getDriverName(), PFAPI.pf_getNFEventHandler()) != 0)
            {
                PFAPI.pf_free();
                return;
            }

            NFAPI.nf_setTCPTimeout(0);

            NF_RULE rule = new NF_RULE();

            // Filter all TCP connections 
            rule.protocol = (int)ProtocolType.Tcp;
            rule.filteringFlag = (uint)NF_FILTERING_FLAG.NF_FILTER;
            NFAPI.nf_addRule(rule, 0);

            Console.In.ReadLine();

            NFAPI.nf_free();
            PFAPI.pf_free();
        }
    }
}
