using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Tarea8PKI 
{
    class Program
    {
        static List<X509Certificate> parents;
        static string rutaCertRaiz = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\CA-RAIZ_RAIZ-CA.crt";
        static string rutaCertEmisora = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\EMISORA.coviticos.pki_coviticos-EMISORA-CA.cer";
        static string rutaCrlRaiz = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\RAIZ-CA.crl";
        static string rutaCrlEmisora = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\coviticos-EMISORA-CA.crl";

        static void Main(string[] args)
        {  
            

            Console.WriteLine("PKI - Tarea 8");
            Console.WriteLine("Cargando certificados y CRLs de CA raiz y emisora...");

            parents = loadRootAndIssuer(rutaCertRaiz, rutaCertEmisora);
            
            // Selecionar accion
            Console.WriteLine("Seleccione una opcion con el respectivo numero:");
            Console.WriteLine("1.	Hacer un proceso de autenticación simple mediante certificado digital.");
            Console.WriteLine("2.	Generar una firma digital (PKCS#7/CMS).");
            Console.WriteLine("3.	Solicitar una estampa de tiempo a la TSA SINPE.");
            Console.WriteLine("4.	Test de llaves.");

            char inputChar = Console.ReadKey().KeyChar;
            if(inputChar == '2')
            {
                generateSign();
                
            }
        
            if(inputChar == '4')
            {
                keysTest();
            }
            
            // 1.	Hacer un proceso de autenticación simple mediante certificado digital.

            
        }

        static void generateSign()
        {
            var path = @"C:\Users\User\Desktop\firmado.data";
            string text = "Este archivo esta firmado";
            byte[] data = Encoding.ASCII.GetBytes(text);

            Console.WriteLine("Cargando certificado desde: C:\\Users\\User\\Desktop\\5to año compu\\llave pública\\mi certificado\\certificado.cer");
            Console.WriteLine("Cargando llave desde: C:\\Users\\User\\Desktop\\5to año compu\\llave pública\\mi certificado\\key.pem");
            string rutaCertificado = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\certificado.cer";
            string rutaLlavePrivada = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\key.pem";
            
            X509Certificate certificado = LoadCertificate(rutaCertificado);
            RsaKeyParameters PublicKey = (RsaKeyParameters)certificado.GetPublicKey();
            RsaKeyParameters PrivateKey = (RsaKeyParameters)ReadAsymmetricKeyParameter(rutaLlavePrivada);
            
            
            //X509Certificate prueba = parents[1];
            //prueba.Verify(parents[0].GetPublicKey());

            byte[] signedData = Sign(data, 
                                PrivateKey, 
                                certificado, 
                                BuildCertificateChain(certificado, parents) );
            File.WriteAllBytes(path, signedData);
            Console.WriteLine("The data has been written to the file.");
        }

        static void keysTest()
        {
            Console.WriteLine();
            Console.WriteLine("Cargando certificado desde: C:\\Users\\User\\Desktop\\5to año compu\\llave pública\\mi certificado\\certificado.cer");
            Console.WriteLine("Cargando llave desde: C:\\Users\\User\\Desktop\\5to año compu\\llave pública\\mi certificado\\key.pem");
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

        // Se manejan solo dos parametros por la simplicidad de la infraestructura  
        static List<X509Certificate> loadRootAndIssuer(string rootPath, string issuerPath)
        {
            List<X509Certificate> parents = new List<X509Certificate>();
            parents.Add(LoadCertificate(rootPath));
            parents.Add(LoadCertificate(issuerPath));
            return parents;
        }
             
        // https://stackoverflow.com/questions/10724594/build-certificate-chain-in-bouncycastle-in-c-sharp
        static List<X509Certificate> BuildCertificateChain(X509Certificate primary, List<X509Certificate> additional)
        {
            X509CertificateParser parser = new X509CertificateParser();
            PkixCertPathBuilder builder = new PkixCertPathBuilder();

            // Separate root from itermediate
            List<X509Certificate> intermediateCerts = new List<X509Certificate>();
            HashSet rootCerts = new HashSet();

            foreach (X509Certificate cert in additional)
            {
                // Separate root and subordinate certificates
                if (cert.IssuerDN.Equivalent(cert.SubjectDN))
                {
                    rootCerts.Add(new TrustAnchor(cert, null));
                    intermediateCerts.Add(cert);
                }
                else
                    intermediateCerts.Add(cert);
            }

            // Create chain for this certificate
            X509CertStoreSelector holder = new X509CertStoreSelector();
            holder.Certificate = primary;

            // WITHOUT THIS LINE BUILDER CANNOT BEGIN BUILDING THE CHAIN
        intermediateCerts.Add(holder.Certificate);

            PkixBuilderParameters builderParams = new PkixBuilderParameters(rootCerts, holder);
            builderParams.IsRevocationEnabled = false;

            X509CollectionStoreParameters intermediateStoreParameters =
                new X509CollectionStoreParameters(intermediateCerts);

            builderParams.AddStore(X509StoreFactory.Create(
                "Certificate/Collection", intermediateStoreParameters));

            PkixCertPathBuilderResult result = builder.Build(builderParams);
            
            return (List<X509Certificate>)result.CertPath.Certificates.Cast<X509Certificate>().ToList();
        }

        // https://csharp.hotexamples.com/site/file?hash=0x4aa3e7386cd74654bc3bcdb77943e7806d3f6142cc78f1c24a16806d30fd6add&fullName=csharp/tools/trust.bundler/FileSignerProvider.cs&project=DM-TOR/nhin-d
        public static byte[] Sign(byte[] data, RsaKeyParameters key, X509Certificate signCert, List<X509Certificate> certChain)
        {
            var generator = new CmsSignedDataGenerator();
            // Add signing key
            generator.AddSigner(
            key,
            signCert,
            "2.16.840.1.101.3.4.2.1"); // SHA256 digest ID
            var storeCerts = new List<X509Certificate>();
            storeCerts.Add(signCert); // NOTE: Adding end certificate too
            storeCerts.AddRange(certChain); // I'm assuming the chain collection doesn't contain the end certificate already
            // Construct a store from the collection of certificates and add to generator
            var storeParams = new X509CollectionStoreParameters(storeCerts);
            var certStore = X509StoreFactory.Create("CERTIFICATE/COLLECTION", storeParams);
            generator.AddCertificates(certStore);

            // Generate the signature
            var signedData = generator.Generate(
            new CmsProcessableByteArray(data),
            false); // encapsulate = false for detached signature
            return signedData.GetEncoded();
        }

    }
}
