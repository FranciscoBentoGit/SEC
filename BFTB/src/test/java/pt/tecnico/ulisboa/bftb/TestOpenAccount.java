package pt.tecnico.ulisboa.bftb;

import static org.junit.Assert.assertTrue;

import java.io.*;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import pt.tecnico.ulisboa.bftb.client.ClientApp;
import pt.tecnico.ulisboa.bftb.client.Library;
import pt.tecnico.ulisboa.bftb.server.ServerApp;
import pt.tecnico.ulisboa.bftb.server.ServerImpl;

/**
 * Unit test for simple App.
 */
public class TestOpenAccount 
{


    /**
     * Open an account with success
     */
    @Test
    public void openAccount00()
    {
        KeyStore keyStore;
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        String user = "client1";
        String passwd = "secret1";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user,protParam);
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey, request) + " " + request;

            response = ServerApp.open_account(signedRequest.split(" "), true).split(" ", 2)[1];
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'openAccount00()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs + "!" + "The account was created with success.\n"));
 
        ServerImpl.reset();
    }


    /**
     * Replay attack on open account
     */
    @Test
    public void openAccount01()
    {
        KeyStore keyStore;
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        String user = "client1";
        String passwd = "secret1";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user,protParam);
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey, request) + " " + request;

            ServerApp.open_account(signedRequest.split(" "), true);
            response = ServerApp.open_account(signedRequest.split(" "), true).split(" ", 2)[1];
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'openAccount01()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs + "!" + "Error: Replay attack detected.\n"));

        ServerImpl.reset();
    }


    /**
     * Duplicated account on open account
     */
    @Test
    public void openAccount02()
    {
        KeyStore keyStore;
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        String user = "client1";
        String passwd = "secret1";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user,protParam);
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            signedRequest = ClientApp.signMessage(privateKey, request) + " " + request;
            response = ServerApp.open_account(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'openAccount02()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs + "!" + "Error: Public key already in use.\n"));
   
        ServerImpl.reset();
    }


    /**
     * Try to open account with incompatible signature-public key
     */
    @Test
    public void openAccount03()
    {
        KeyStore keyStore;
        PublicKey victimPublicKey = null;
        PrivateKey privateKey = null;
        int victimClientID = 2;
        String evilUser = "client1";
        String passwd = "secret1";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(evilUser,protParam);
            privateKey = privateKeyEntry.getPrivateKey();

            victimPublicKey = Library.stringToPublicKey(ClientApp.getPublicKeyByID(victimClientID));
            
            request = "open_account" + " " + Base64.getEncoder().encodeToString(victimPublicKey.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            signedRequest = ClientApp.signMessage(privateKey, request) + " " + request;
            response = ServerApp.open_account(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'openAccount03()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs + "!" + "Error: Invalid signature.\n"));

        ServerImpl.reset();
    }


    /**
     * Open account request is corrupted
     */
    @Test
    public void openAccount04()
    {
        KeyStore keyStore;
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        String user = "client1";
        String passwd = "secret1";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user,protParam);
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + wTs;
            String corrupted_request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "corruptedRequest" + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey, request) + " " + corrupted_request;

            response = ServerApp.open_account(signedRequest.split(" "), true).split(" ", 2)[1];
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'openAccount04()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs + "!" + "Error: Invalid signature.\n"));
 
        ServerImpl.reset();
    }



}
