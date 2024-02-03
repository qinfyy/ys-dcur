using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using Google.Protobuf;
using Dispatch;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Newtonsoft.Json;

namespace Cur
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class OpenFileName
        {
            public int lStructSize;
            public IntPtr hwndOwner;
            public IntPtr hInstance;
            public string lpstrFilter;
            public string lpstrCustomFilter;
            public int nMaxCustFilter;
            public int nFilterIndex;
            public string lpstrFile;
            public int nMaxFile;
            public string lpstrFileTitle;
            public int nMaxFileTitle;
            public string lpstrInitialDir;
            public string lpstrTitle;
            public int Flags;
            public short nFileOffset;
            public short nFileExtension;
            public string lpstrDefExt;
            public IntPtr lCustData;
            public IntPtr lpfnHook;
            public string lpTemplateName;
            public IntPtr pvReserved;
            public int dwReserved;
            public int FlagsEx;
        }

        [DllImport("comdlg32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool GetSaveFileName([In, Out] OpenFileName ofn);

        static string SaveFile()
        {
            OpenFileName ofn = new OpenFileName
            {
                lStructSize = Marshal.SizeOf(typeof(OpenFileName)),
                lpstrFilter = "Json文件 (*.json)\0*.json\0所有文件 (*.*)\0*.*\0",
                lpstrFile = new string('\0', 260),
                nMaxFile = 260,
                lpstrFileTitle = new string('\0', 100),
                nMaxFileTitle = 100,
                Flags = 0x00000002 | 0x00000004 | 0x00000008 | 0x00080000,
                lpstrTitle = "保存"
            };
            if (GetSaveFileName(ofn))
            {
                return ofn.lpstrFile;
            }
            else
            {
                return null;
            }
        }

        private static AsymmetricCipherKeyPair GetAsymmetricCipherKeyPairFromPem(string pemKey)
        {
            using (TextReader reader = new StringReader(pemKey))
            {
                PemReader pemReader = new PemReader(reader);
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                if (keyPair != null)
                {
                    return keyPair;
                }
                throw new Exception("PEM 私钥格式无效");
            }
        }

        private static RsaKeyParameters GetRsaKeyParametersFromPem(string pemKey)
        {
            using (TextReader reader = new StringReader(pemKey))
            {
                PemReader pemReader = new PemReader(reader);
                RsaKeyParameters publicKeyParams = (RsaKeyParameters)pemReader.ReadObject();
                if (publicKeyParams != null)
                {
                    return publicKeyParams;
                }
                throw new Exception("PEM 公钥格式无效");
            }
        }

        static void Main()
        {
            string pubKeyPath = "ServerPub.pem";
            string privKeyPath = "ClientPri.pem";

            string privKeyText = File.ReadAllText(privKeyPath);
            string pubKeyText = File.ReadAllText(pubKeyPath);

            AsymmetricCipherKeyPair keyPair = GetAsymmetricCipherKeyPairFromPem(privKeyText);
            RsaPrivateCrtKeyParameters privKeyParameters = (RsaPrivateCrtKeyParameters)keyPair.Private;
            RSAParameters rsaPrivParameters = DotNetUtilities.ToRSAParameters(privKeyParameters);

            RSACryptoServiceProvider rsaPrivate = new RSACryptoServiceProvider();
            rsaPrivate.ImportParameters(rsaPrivParameters);

            RsaKeyParameters pubKeyParameters = GetRsaKeyParametersFromPem(pubKeyText);
            RSAParameters rsaPubParameters = DotNetUtilities.ToRSAParameters(pubKeyParameters);

            RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();
            rsaPublic.ImportParameters(rsaPubParameters);

            string DataFile = "data.txt";
            if (!File.Exists(DataFile))
            {
                Console.WriteLine($"{DataFile} 不存在");
                Console.Write("请按任意键继续...");
                Console.ReadKey();
                Environment.Exit(0);
            }
            string jsonData = File.ReadAllText(DataFile);

            dynamic parsedData = JsonConvert.DeserializeObject(jsonData);

            string contentBase64 = parsedData.content;
            string signBase64 = parsedData.sign;

            byte[] content = Convert.FromBase64String(contentBase64);
            byte[] sign = Convert.FromBase64String(signBase64);

            int keySizeBytes = 256; // 2048 位密钥为 256 字节
            List<byte> decryptedData = new List<byte>();

            for (int i = 0; i < content.Length; i += keySizeBytes)
            {
                int blockSize = Math.Min(keySizeBytes, content.Length - i);
                byte[] block = new byte[blockSize];
                Array.Copy(content, i, block, 0, blockSize);

                byte[] decryptedBlock = rsaPrivate.Decrypt(block, false);
                decryptedData.AddRange(decryptedBlock);
            }

            byte[] result = decryptedData.ToArray();

            bool verified = rsaPublic.VerifyData(result, CryptoConfig.MapNameToOID("SHA256"), sign);

            Console.WriteLine("验证签名: " + verified);

            MemoryStream stream = new MemoryStream(result);
            QueryCurrRegionHttpRsp message = QueryCurrRegionHttpRsp.Parser.ParseFrom(stream);
            stream.Close();
            string JsonOutput = JsonFormatter.ToDiagnosticString(message);
            string FormattedJson = JsonConvert.SerializeObject(JsonConvert.DeserializeObject(JsonOutput), Formatting.Indented);
            string FilePath = SaveFile();
            if (FilePath == null)
            {
                Console.WriteLine("用户未选择保存文件");
            }
            else
            {
                File.WriteAllText(FilePath, FormattedJson);
                Console.WriteLine($"JSON 数据已保存到文件: {FilePath}");
                Console.WriteLine("解码已完成");
            }
            Console.Write("请按任意键继续...");
            Console.ReadKey();
        }
    }
}
