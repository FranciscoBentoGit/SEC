package pt.tecnico.ulisboa.bftb;

import org.apache.commons.io.IOUtils;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.*;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class KeyStoreService {

	private static int NUMBER_OF_SERVERS = 4; //change in future
	private static int NUMBER_OF_CLIENTS = 10;
	/**
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyStoreService keystoreService = new KeyStoreService();
		FileWriter clientfw = new FileWriter("client-files/publicKeyRecord.txt", false);
		FileWriter serverfw = new FileWriter("server-files/publicKeyRecord.txt", false);
		BufferedWriter clientbw = new BufferedWriter(clientfw);
		BufferedWriter serverbw = new BufferedWriter(serverfw);
		PrintWriter clientPublicKeyStore = new PrintWriter(clientbw);
		PrintWriter serverPublicKeyStore = new PrintWriter(serverbw);
		KeyStore clientKeyStore = keystoreService.createKeyStore("password");
		KeyStore serverKeyStore = keystoreService.createKeyStore("password");

		String[] certPrivateKey;
		String passwd;
		for (int i = 1; i < NUMBER_OF_CLIENTS+1; i++) {
			certPrivateKey = keystoreService.createCertPrivateKey(clientPublicKeyStore);
			passwd = "secret" + i;
			keystoreService.addPrivateKey(clientKeyStore, "client" + i, certPrivateKey[1], certPrivateKey[0], passwd);
		}

		for (int i = 0; i < NUMBER_OF_SERVERS; i++) {
			certPrivateKey = keystoreService.createCertPrivateKey(serverPublicKeyStore);
			passwd = "secret" + i;
			keystoreService.addPrivateKey(serverKeyStore, "server" + i, certPrivateKey[1], certPrivateKey[0], passwd);
		}

		keystoreService.saveKeyStore(serverKeyStore,"password", "server");
		keystoreService.saveKeyStore(clientKeyStore,"password", "client");

		clientPublicKeyStore.close();
		serverPublicKeyStore.close();
		clientbw.close();
		serverbw.close();
		clientfw.close();
		serverfw.close();
	}


	/**
	 * 
	 * @param passwd
	 * @return
	 */
	public KeyStore createKeyStore(String passwd) {
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS"); //maybe JCEKS??
			char[] pwdArray = passwd.toCharArray();
			keyStore.load(null, pwdArray);
			return keyStore;
		} catch (Exception e) {
			//too many exceptions we can't handle, so brute force catch
			throw new RuntimeException(e);
		}
	}


	/**
	 * 
	 * @param keyStore
	 * @param passwd
	 * @param source
	 */
	public void saveKeyStore(KeyStore keyStore, String passwd, String source) {
		try (FileOutputStream fos = new FileOutputStream(source + "-files/keystorefile.jks")) {
			char[] pwdArray = passwd.toCharArray();
			keyStore.store(fos,pwdArray);
			fos.close();
			return;
		} catch (Exception e) {
			//too many exceptions we can't handle, so brute force catch
			throw new RuntimeException(e);
		}
	}


	/**
	 * 
	 * @param keyStore
	 * @param client
	 * @param passwd
	 * @return
	 */
	public KeyStore readEntry(KeyStore keyStore, String client, String passwd) {
		try {
			print(client);
			print(passwd);
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
			PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(client,protParam);
			String certificate = new String(Base64.getEncoder().encode(privateKeyEntry.getCertificate().getEncoded()));
			String privateKey = new String(Base64.getEncoder().encode(privateKeyEntry.getPrivateKey().getEncoded()));
			String publicKey = new String(Base64.getEncoder().encode(privateKeyEntry.getCertificate().getPublicKey().getEncoded()));
			print("-------------------");
			print(certificate);
			print("-------------------");
			print(privateKey);
			print("-------------------");
			print(publicKey);

			return keyStore;

		} catch (Exception e) {
			//too many exceptions we can't handle, so brute force catch
			throw new RuntimeException(e);
		}
	}

	
	/**
	 * 
	 * @param keyStore
	 * @param client
	 * @param privateKey
	 * @param certificate
	 * @param password
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 */
	//privateKey must be in the DER unencrypted PKCS#8 format.
	public void addPrivateKey(KeyStore keyStore, String client, String privateKey, String certificate, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException, CertificateException {
		String wrappedCert = wrapCert(certificate);
		byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());

		char[] passwordChars = password.toCharArray();
		CertificateFactory certFact = CertificateFactory.getInstance("X.509");
		java.security.cert.Certificate cert = certFact.generateCertificate(new ByteArrayInputStream(wrappedCert.getBytes()));
		ArrayList<java.security.cert.Certificate> certs = new ArrayList<>();
		certs.add(cert);

		byte[] privKeyBytes = IOUtils.toByteArray(new ByteArrayInputStream(decodedKey));

		KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
		RSAPrivateKey privKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(ks);
		keyStore.setKeyEntry(client, privKey, passwordChars, certs.toArray(new java.security.cert.Certificate[certs.size()]));
	}

	
	public String[] createCertPrivateKey(PrintWriter publicKeyStore) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IOException, CertificateException, SignatureException {
		CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
		certGen.generate(2048);
		long validSecs = 10 * 365 * 24 * 60 * 60;

		X509Certificate certificate = certGen.getSelfCertificate(new X500Name("CN=AttributeMapper,O=SURFnet,L=Utrecht,C=NL"), validSecs);
		String certificatePublicKey = new String(Base64.getEncoder().encode(certificate.getEncoded()));
		String privateKey = new String(Base64.getEncoder().encode(certGen.getPrivateKey().getEncoded()));
		String publicKey = new String(Base64.getEncoder().encode(certGen.getPublicKey().getEncoded()));
		storePublicKey(publicKey,publicKeyStore);

		return new String[] {certificatePublicKey, privateKey};
	}

	
	/**
	 * 
	 * @param publicKey
	 * @param publicKeyStore
	 * @throws FileNotFoundException
	 */
	private void storePublicKey(String publicKey, PrintWriter publicKeyStore) throws FileNotFoundException {
		publicKeyStore.println(publicKey);
	}


	/**
	 * 
	 * @param certificate
	 * @return
	 */
	private String wrapCert(String certificate) {
		return "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----";
	}


	/**
	 * 
	 * @param text
	 */
	public static void print(Object text) {
		System.out.println(text);
	}


}