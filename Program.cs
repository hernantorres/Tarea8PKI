using System;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace Tarea8PKI 
{
    class Program
    {
        

        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            // Selecionar accion
            Console.WriteLine("Seleccione una opcion con el respectivo numero:");
            Console.WriteLine("1.	Hacer un proceso de autenticación simple mediante certificado digital.");
            Console.WriteLine("2.	Generar una firma digital (básica, en formatos PKCS#7/CMS, PDF o XMLDsig).");
            Console.WriteLine("3.	Solicitar una estampa de tiempo a la TSA SINPE.");
            Console.WriteLine("4.	Test de llaves.");

            char inputChar = Console.ReadKey().KeyChar;
            if(inputChar == '4')
            {
                Console.WriteLine();
                Console.WriteLine("Cargando certificado desde: C:\\Users\\User\\Desktop\\5to año compu\\llave pública\\mi certificado\\certificado.cer");
                Console.WriteLine("Cargando certificado desde: C:\\Users\\User\\Desktop\\5to año compu\\llave pública\\mi certificado\\key.pem");
                string rutaCertificado = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\certificado.cer";
                string rutaLlavePrivada = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\key.pem";
                
                X509Certificate certificado = LoadCertificate(rutaCertificado);
                
                // https://stackoverflow.com/questions/51428083/how-do-i-get-the-organization-name-from-an-x509certificate2
                var name = new X509Name(certificado.SubjectDN.ToString());
                var cedula = name.GetValueList(X509Name.SerialNumber).OfType<string>().FirstOrDefault();; 
                
                // Esta otra forma da todo el subject pero esta ordenado al reves
                //string cn = certificado.SubjectDN.ToString();
                //Console.WriteLine();
                
                Console.WriteLine("El cédula de la persona es: " + cedula);
               
                RsaKeyParameters PublicKey = (RsaKeyParameters)certificado.GetPublicKey();
                RsaKeyParameters PrivateKey = (RsaKeyParameters)ReadAsymmetricKeyParameter(rutaLlavePrivada);

                string SrcData = "Este texto indica que las llaves se relacionan.";
                byte[] SrcBytes = Encoding.ASCII.GetBytes(SrcData);

                byte[] ciphered = Encrypt(SrcBytes, PublicKey); 
                string cipheredText = Encoding.UTF8.GetString(ciphered);
                Console.WriteLine();
                Console.WriteLine("Texto cifrado: {0}", cipheredText);
                Console.WriteLine();

                byte[] deciphered = Decrypt(ciphered, PrivateKey);
                string decipheredText = Encoding.UTF8.GetString(deciphered);
                Console.WriteLine();
                Console.WriteLine("Texto decifrado: {0}\n", decipheredText);
                Console.WriteLine();

            }
            
            // 1.	Hacer un proceso de autenticación simple mediante certificado digital.

            
        }

        static X509Certificate LoadCertificate(string filename)
        {
            X509CertificateParser certParser = new X509CertificateParser();
            FileStream fs = new FileStream(filename, FileMode.Open);
            X509Certificate cert = certParser.ReadCertificate(fs);
            fs.Close();

            return cert;
        }

        static AsymmetricKeyParameter ReadAsymmetricKeyParameter(string pemFilename)
        {
            var fileStream = System.IO.File.OpenText(pemFilename);
            var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(fileStream);
            var KeyParameter = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)pemReader.ReadObject();
            return KeyParameter;
        }

        static byte[] Encrypt(byte[] plainText, RsaKeyParameters PublicKey)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());
            cipher.Init(true, PublicKey);
            byte[] ciphered = cipher.ProcessBlock(plainText, 0, plainText.Length);
            return ciphered;
        }

        static byte[] Decrypt(byte[] cipherText, RsaKeyParameters PrivateKey)
        {
            IAsymmetricBlockCipher decipher = new OaepEncoding(new RsaEngine());
            decipher.Init(false, PrivateKey);
            byte[] deciphered = decipher.ProcessBlock(cipherText, 0, cipherText.Length);
            return  deciphered;
        }
             
    }
}
