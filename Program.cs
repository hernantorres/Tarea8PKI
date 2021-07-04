using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Tarea8PKI 
{
    class Program
    {
        // Certificados de CA Raiz y Emisora
        static List<X509Certificate> parentsCerts;
        static List<X509Crl> parentsCrls;
        static List<X509Certificate> usersCerts;
        static string tokenTruth = "PKI2020";
        static string rutaCertRaiz = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\CA-RAIZ_RAIZ-CA.crt";
        static string rutaCertEmisora = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\EMISORA.coviticos.pki_coviticos-EMISORA-CA.cer";
        static string rutaCrlRaiz = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\RAIZ-CA.crl";
        static string rutaCrlEmisora = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\coviticos-EMISORA-CA.crl";


        static void Main(string[] args)
        {  
            
            Console.WriteLine("PKI - Tarea 8");
            Console.WriteLine("Cargando certificados y CRLs...");
            parentsCerts = loadParentsCerts(rutaCertRaiz, rutaCertEmisora);
            parentsCrls = loadParentsCrls(rutaCrlRaiz, rutaCrlEmisora);

            // Solo contamos con un usuario
            Console.WriteLine("Cargando usuarios...");
            usersCerts = new  List<X509Certificate>();
            usersCerts.Add(LoadCertificate(@"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\certificado.cer"));
            
            bool correct = true;

            // Selecionar accion
            Console.WriteLine("Seleccione una opcion con el respectivo numero:");
            Console.WriteLine("1.	Hacer un proceso de autenticación simple mediante certificado digital.");
            Console.WriteLine("2.	Generar una firma digital (PKCS#7/CMS).");
            Console.WriteLine("3.	Solicitar una estampa de tiempo a la TSA SINPE.");
            Console.WriteLine("4.	Test de llaves.");
            Console.WriteLine("5.	Salir.");
            Console.WriteLine();

            char inputChar = Console.ReadKey().KeyChar;
            

            if(inputChar == '1')
            {
                // Aca decide si quiere obtener un token de autenticacion o autenticarse
                authenticateViaCertificate(); 
            }
            else if(inputChar == '2')
            {
                generateCmsSign();
                
            }
            else if(inputChar == '3')
            {
                // sinpeTimeStamp();
            }
            else if(inputChar == '4')
            {
                keysTest();
            }
            else if(inputChar == '5')
            {
                correct = false;
            }
            else
            {
                Console.WriteLine("Opccion incorrecta");
            }    
        }

        static void authenticateViaCertificate()
        {
            bool correct = true;

            Console.WriteLine("Seleccione una opcion con el respectivo numero:");
            Console.WriteLine("1.	Obtener un token de autenticacion.");
            Console.WriteLine("2.	Autenticarse.");
            Console.WriteLine("3.	Volver.");

            char inputChar = Console.ReadKey().KeyChar;
            
            if(inputChar == '1')
            {
                generateAuthToken();
            }
            else if(inputChar == '2')
            {
                authenticateCertAndToken();
                
            }
            else if(inputChar == '5')
            {
                correct = false;
            }
            else
            {
                Console.WriteLine("Opccion incorrecta");
            }


        } 

        static void generateAuthToken()
        {
            Console.WriteLine("Generando token para HERNAN TORRES NUÑEZ");
            string rutaLlavePrivada = @"C:\Users\User\Desktop\5to año compu\llave pública\mi certificado\key.pem";
            RsaKeyParameters PrivateKey = (RsaKeyParameters)ReadAsymmetricKeyParameter(rutaLlavePrivada);
            byte[] token = GenerateSimpleSignature(tokenTruth, PrivateKey);

            string tokenPath = @"C:\Users\User\Desktop\token";
            File.WriteAllBytes(tokenPath, token);
            Console.WriteLine("Token guardado en: C:\\Users\\User\\Desktop\\token");
        }

        static void authenticateCertAndToken()
        {
            Console.WriteLine("Para autenticarse provea los siguientes elementos:");
            Console.WriteLine("Ruta de su certificado:");
            string certPath = Console.ReadLine();
            Console.WriteLine("Ruta de su token:");
            string tokenPath = Console.ReadLine();

            X509Certificate cert = LoadCertificate(certPath);
            byte[] signature = File.ReadAllBytes(tokenPath);

            // Construimos la cadena del certificado
            Console.WriteLine("Construyendo cadena de certificados...");
            BuildCertificateChain(cert, parentsCerts);

            // Verificamos su estado en el CRL de la CA EMISORA
            Console.WriteLine("Verificando estado del certificado...");
            bool revocado = checkRevocation(cert,  parentsCrls[1]);

            bool valido = ValidateSimpleSignature(tokenTruth, 
                                                    signature, 
                                                    (RsaKeyParameters)cert.GetPublicKey());
            // Chequear que el token es valido y el certificado no esta revocado (la cadena falla al construirce)
            if (valido && !revocado)
            {
                var name = new X509Name(cert.SubjectDN.ToString());
                var nombre = name.GetValueList(X509Name.CN).OfType<string>().FirstOrDefault();
                var cedula = name.GetValueList(X509Name.SerialNumber).OfType<string>().FirstOrDefault();
                Console.WriteLine("Autenticado!");
                Console.WriteLine("Usuario: " + nombre);
                Console.WriteLine("Cédula: " + cedula);
            }
            else
            {
                Console.WriteLine("Fallo en autenticación, el certificado es el incorrecto, o no se reconoce su token.");
            }



        }

        // https://gist.github.com/itsho/98bbb6d668b18072b6ffdf089ef28fc2
        static bool ValidateSimpleSignature(string sourceData, byte[] signature, RsaKeyParameters publicKey)
		{
			byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

			ISigner signClientSide = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
			signClientSide.Init(false, publicKey);
			signClientSide.BlockUpdate(tmpSource, 0, tmpSource.Length);

			return  signClientSide.VerifySignature(signature);
		}

        // https://gist.github.com/itsho/98bbb6d668b18072b6ffdf089ef28fc2
		static byte[] GenerateSimpleSignature(string sourceData, RsaKeyParameters privateKey)
		{
			byte[] tmpSource = Encoding.ASCII.GetBytes(sourceData);

			ISigner sign = SignerUtilities.GetSigner(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id);
			sign.Init(true, privateKey);
			sign.BlockUpdate(tmpSource, 0, tmpSource.Length);
			return sign.GenerateSignature();
		}

    
        // Genera la firma llamando a sign
        static void generateCmsSign()
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

            byte[] signedData = cmsSign(data, //mensaje para crear firma
                                PrivateKey, // llave privada
                                certificado, // certificado de mi persona
                                BuildCertificateChain(certificado, parentsCerts) ); // certificado de CA raiz y emisora
            File.WriteAllBytes(path, signedData);
            Console.WriteLine("La firma se ha escrito en: C:\\Users\\User\\Desktop\\firmado.data");
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

        static X509Crl LoadCrl(string filename)
        {
            X509CrlParser certParser = new X509CrlParser();
            FileStream fs = new FileStream(filename, FileMode.Open);
            X509Crl crl = certParser.ReadCrl(fs);
            fs.Close();

            return crl;
        }

        static bool checkRevocation(X509Certificate cert, X509Crl crl)
        {
             bool result = crl.IsRevoked(cert);
             return result;
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
        static List<X509Certificate> loadParentsCerts(string rootPath, string issuerPath)
        {
            List<X509Certificate> parents = new List<X509Certificate>();
            parents.Add(LoadCertificate(rootPath));
            parents.Add(LoadCertificate(issuerPath));
            return parents;
        }

        static List<X509Crl> loadParentsCrls(string rootPath, string issuerPath)
        {
            List<X509Crl> parents = new List<X509Crl>();
            parents.Add(LoadCrl(rootPath));
            parents.Add(LoadCrl(issuerPath));
            return parents;
        }
             
        // https://stackoverflow.com/questions/10724594/build-certificate-chain-in-bouncycastle-in-c-sharp
        // Lanza una excepcion si no se puede verificar la cadena
        // ToDo: capturar excepcion
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
        public static byte[] cmsSign(byte[] data, RsaKeyParameters key, X509Certificate signCert, List<X509Certificate> certChain)
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
