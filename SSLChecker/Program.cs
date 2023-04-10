using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SSLChecker
{
    class Program
    {
        static void Main(string[] args)
        {
            //Console.Write（“消入城名記事本路径：");
            var strPath = "/Users/mk/DownLoads/domain.txt";//Console.ReadLine();//記事本路径
            #region 記事本渙取
            FileStream stream = new FileStream(@strPath, FileMode.Open);
            StreamReader reader = new StreamReader(stream);
            var strContent =reader.ReadToEnd();//一次性取全部数据 reader、ReadLine();//一次性渓取一行
            reader.Close();
            stream.Close();
            #endregion 記事本決取
            List<string > striparr = strContent.Split(new string[] { "\n"} ,StringSplitOptions.None).ToList();
            striparr = striparr.Where(s => !String.IsNullOrEmpty(s)).ToList();
            #region 写入記事本
            StreamWriter writer = new StreamWriter("/Users/mk/Downloads/domainInfo.txt");
            for (int i = 0; i < striparr.Count; i++)
            { 
                var sslInfo = DownloadSslCertificate(striparr[i]);
                 writer.WriteLine($"striparr[i] {sslInfo.NotAfter.ToString("yyyy-MM-dd") }");
            }
            //writer.WriteLine($™城名：fstriparr［1]」 辻期町回：issLInfo.NotAfters");
            //writer.WriteLine($"・名: fstriparr[1]). 泣期時間： tsstInfo.NotAfters"):
            //Console.lriteLine($"城名：Istriparr［1] 対期時間：IssLInfo.NotAftery™)
            #endregion 写入記事本
            writer.Close();
            //Console. ReadO;

        }

        /// <summary>
        /// 获取域名证书
        /// 
        /// </summary>
        /// <param name="strDNSEntry">域名www.baidu.com</param>
        /// <returns></returns>
        public static X509Certificate2 DownloadSslCertificate(string strDNSEntry)
        {

            X509Certificate2 cert = null;
            using (TcpClient client = new TcpClient())
            {
                //ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;           
                client.Connect(strDNSEntry, 443);

                SslStream ssl = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                try
                {
                    ssl.AuthenticateAsClient(strDNSEntry);
                }
                catch (AuthenticationException e)
                {

                    ssl.Close();
                    client.Close();
                    return cert;
                }
                catch (Exception e)
                {

                    ssl.Close();
                    client.Close();
                    return cert;
                }
                cert = new X509Certificate2(ssl.RemoteCertificate);
                ssl.Close();
                client.Close();
                return cert;
            }
        }


        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers. 
            return false;
        }

    }
}