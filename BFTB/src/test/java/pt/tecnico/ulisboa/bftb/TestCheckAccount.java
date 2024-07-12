package pt.tecnico.ulisboa.bftb;

import static org.junit.Assert.assertTrue;

import java.io.*;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import java.util.Base64;

import org.bouncycastle.jcajce.provider.symmetric.Rijndael;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import pt.tecnico.ulisboa.bftb.client.ClientApp;
import pt.tecnico.ulisboa.bftb.client.Library;
import pt.tecnico.ulisboa.bftb.server.ServerApp;
import pt.tecnico.ulisboa.bftb.server.ServerImpl;
import pt.tecnico.ulisboa.bftb.server.Transaction;

/**
 * Unit test for simple App.
 */
public class TestCheckAccount
{   

    /**
     * Client 1 checks client 2's account with success
     */
    @Test
    public void checkAccount00()
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
            request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'checkAccount00()'");
        }
        
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs + "!check_account!" + ServerImpl.getAccountByPublicKey(publicKey2).getBalance() + "!transactions"));

        ServerImpl.reset();
    }

    /**
     * Client 1 checks client 2's account with success
     */
    @Test
    public void checkAccount01()
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
        Transaction t = null;
        int wTs1 = 1;
        int wTs2 = 1;
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
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //send money from client 2 to client 1
            wTs2++;
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + amount + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;

            ServerApp.send_amount(signedRequest.split(" "), true);

            //client 2 audit client 1 transaction's
            request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;

            response = ServerImpl.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

            t = ServerImpl.getTransactionByID(transactionID);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'checkAccount00()'");
        }

        assertTrue(response.equals( signedRequest.split(" ")[0] + "!" + rID + "!" + wTs1 + "!" 
                        + "check_account!10000!"
                        + t.representation() + "!transactions" ));

        ServerImpl.reset();
    }

    /**
     * Replay attack on check account
     */
    @Test
    public void checkAccount02()
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
        int wTs1 = 1;
        int wTs2 = 1;
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
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 check client 2 account
            request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            ServerApp.readCheckAccountOrAudit(signedRequest.split(" "));
            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'checkAccount02()'");
        }
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs1  + "!check_account!" + "Error: Replay attack detected.\n"));

        ServerImpl.reset();
    }

    /**
     * Client 1 tries to check client 2 account, but client 1 is not registered
     */
    @Test
    public void checkAccount03()
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
        String wTs1 = "null";
        int wTs2 = 1;
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
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 check client 2 account
            request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'checkAccount02'");
        }
        assertTrue(response.equals(signedRequest.split(" ")[0] +"!" + rID + "!" + "null" + "!check_account!" + "Error: You are not registered\n"));

        ServerImpl.reset();
    }


    /**
     * Client 1 tries to audit client 2 transactions, but client 2 is not registered
     */
    @Test
    public void checkAccount04()
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
        int wTs1 = 1;
        String wTs2 = "null";
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
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();

            //client 1 audit client 2 transactions
            request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'checkAccount03'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs2 + "!check_account!" + "Error: This client is not registered\n"));

        ServerImpl.reset();
    }

    /**
     * Client 1 tries to check client 2 account (invalid signature)
     */
    @Test
    public void checkAccount05()
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
        int wTs1 = 1;
        int wTs2 = 1;
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
            request = "open_account" + " " + Base64.getEncoder().encodeToString(evilPublicKey.getEncoded()) + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(evilPrivateKey, request) + " " + request;
            response = ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            response = ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 check client 2 account, using client 5 public key
            victimPublicKey = Library.stringToPublicKey(ClientApp.getPublicKeyByID(victimClientID));

            request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(victimPublicKey.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(evilPrivateKey, request) + " " + request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'checkAccount05()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs2 + "!check_account!" + "Error: Invalid signature.\n"));

        ServerImpl.reset();
    }


    /**
     * Check account request is corrupted
     */
    @Test
    public void checkAccount06()
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
        int wTs1 = 1;
        int wTs2 = 1;
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
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 audit client 2 transaction's
            request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            String corrupt_request = "check_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + "corrupedRequest" + " " + rID + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + corrupt_request;

            response = ServerApp.readCheckAccountOrAudit(signedRequest.split(" ")).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'checkAccount06()'");
        }
        
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + rID + "!" + wTs1+ "!check_account!" + "Error: Invalid signature.\n"));

        ServerImpl.reset();
    }


}
