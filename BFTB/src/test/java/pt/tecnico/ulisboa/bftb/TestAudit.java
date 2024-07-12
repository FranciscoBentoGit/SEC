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
public class TestAudit
{   

    /**
     * Client 1 audit client 2 transaction's with success
     */
    @Test
    public void audit00()
    {
        KeyStore keyStore;
        PublicKey publicKey1 = null;
        PrivateKey privateKey1 = null;
        PublicKey publicKey2 = null;
        PrivateKey privateKey2 = null;
        String user1 = "client1";
        String passwd1 = "secret1";
        String user2 = "client2";
        String passwd2 = "secret2";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        int rID = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user1,protParam);
            privateKey1 = privateKeyEntry.getPrivateKey();
            publicKey1 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            wTs++;
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 audit client 2 transaction's
            request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'audit00()'");
        }
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs + "!" + "audit!The given account doesn't have any related transactions.\n"));

        ServerImpl.reset();
    }

    /**
     * Client 1 audit client 2 transaction's with success
     */
    @Test
    public void audit01()
    {
        KeyStore keyStore;
        PublicKey publicKey1 = null;
        PrivateKey privateKey1 = null;
        PublicKey publicKey2 = null;
        PrivateKey privateKey2 = null;
        String user1 = "client1";
        String passwd1 = "secret1";
        String user2 = "client2";
        String passwd2 = "secret2";
        String request;
        String signedRequest = null;
        String response = null;
        int transactionID = 1;
        int wTs = 1;
        int rID = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user1,protParam);
            privateKey1 = privateKeyEntry.getPrivateKey();
            publicKey1 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            wTs++;
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //send money from client 2 to client 1
            wTs++;
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + amount + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;

            ServerApp.send_amount(signedRequest.split(" "), true);

            //client 1 audit client 2 transaction's
            request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'audit01()'");
        }
        
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs + "!" + "audit!transactions!" + ServerImpl.getTransactionByID(transactionID).representation()));

        ServerImpl.reset();
    }

    /**
     * Replay attack on audit
     */
    @Test
    public void audit02()
    {
        KeyStore keyStore;
        PublicKey publicKey1 = null;
        PrivateKey privateKey1 = null;
        PublicKey publicKey2 = null;
        PrivateKey privateKey2 = null;
        String user1 = "client1";
        String passwd1 = "secret1";
        String user2 = "client2";
        String passwd2 = "secret2";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        int rID = 1;
       try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user1,protParam);
            privateKey1 = privateKeyEntry.getPrivateKey();
            publicKey1 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            wTs++;
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 audit client 2 transaction's
            request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            ServerApp.readCheckAccountOrAudit(signedRequest.split(" "));

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'audit02()'");
        } 
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs + "!audit!" + "Error: Replay attack detected.\n"));

        ServerImpl.reset();
    }

    /**
     * Client 1 tries to audit client 2 transactions, but client 1 is not registered
     */
    @Test
    public void audit03()
    {
        KeyStore keyStore;
        PublicKey publicKey1 = null;
        PrivateKey privateKey1 = null;
        PublicKey publicKey2 = null;
        PrivateKey privateKey2 = null;
        String user1 = "client1";
        String passwd1 = "secret1";
        String user2 = "client2";
        String passwd2 = "secret2";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        int rID = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user1,protParam);
            privateKey1 = privateKeyEntry.getPrivateKey();
            publicKey1 = privateKeyEntry.getCertificate().getPublicKey();

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 audit client 2 transaction's
            request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'audit03'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + "null" + "!audit!" + "Error: You are not registered\n"));

        ServerImpl.reset();
    }


    /**
     * Client 1 tries to audit client 2 transactions, but client 2 is not registered
     */
    @Test
    public void audit04()
    {
        KeyStore keyStore;
        PublicKey publicKey1 = null;
        PrivateKey privateKey1 = null;
        PublicKey publicKey2 = null;
        PrivateKey privateKey2 = null;
        String user1 = "client1";
        String passwd1 = "secret1";
        String user2 = "client2";
        String passwd2 = "secret2";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        int rID = 1;
      try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user1,protParam);
            privateKey1 = privateKeyEntry.getPrivateKey();
            publicKey1 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();

            //client 1 audit client 2 transactions
            request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'audit04'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!null!audit!" + "Error: This client is not registered\n"));

        ServerImpl.reset();
    }

    /**
     * Client 1 tries to audit client 2 transactions (invalid signature)
     */
    @Test
    public void audit05()
    {
        KeyStore keyStore;
        PublicKey evilPublicKey = null;
        PrivateKey evilPrivateKey = null;
        PublicKey publicKey2 = null;
        PrivateKey privateKey2 = null;
        PublicKey victimPublicKey = null;
        int victimClientID = 5;
        String user1 = "client1";
        String passwd1 = "secret1";
        String user2 = "client2";
        String passwd2 = "secret2";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        int rID = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user1,protParam);
            evilPrivateKey = privateKeyEntry.getPrivateKey();
            evilPublicKey = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(evilPublicKey.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(evilPrivateKey, request) + " " + request;
            response = ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            wTs++;
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            response = ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 audit client 2 transactions, using client 5 public key
            victimPublicKey = Library.stringToPublicKey(ClientApp.getPublicKeyByID(victimClientID));

            request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(victimPublicKey.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(evilPrivateKey, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'audit05()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs + "!audit!" + "Error: Invalid signature.\n"));

        ServerImpl.reset();
    }

    /**
     * Audit request is corrupted
     */
    @Test
    public void audit06()
    {
        KeyStore keyStore;
        PublicKey publicKey1 = null;
        PrivateKey privateKey1 = null;
        PublicKey publicKey2 = null;
        PrivateKey privateKey2 = null;
        String user1 = "client1";
        String passwd1 = "secret1";
        String user2 = "client2";
        String passwd2 = "secret2";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs = 1;
        int rID = 1;
       try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user1,protParam);
            privateKey1 = privateKeyEntry.getPrivateKey();
            publicKey1 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            wTs++;
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 audit client 2 transaction's
            request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            String corrupted_request = "audit" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + "corruptedRequest" + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + corrupted_request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'audit06()'");
        }
        
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs + "!audit!" + "Error: Invalid signature.\n"));

        ServerImpl.reset();
    }

}
