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
public class TestSendAmount
{


    /**
     * Send money with success
     */
    @Test
    public void sendAmount00()
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

            //send money from client 1 to client 2
            wTs1++;
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount00()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "The money was sent with success.\n" + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " must accept the transaction.\nYour current balance is : " + ServerImpl.get_accountsMap().get(publicKey1).getBalance() + "\n"));

        ServerImpl.reset();
    }


    /**
     * Replay attack on send amount
     */
    @Test
    public void sendAmount01()
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

            //send money from client 1 to client 2
            wTs1++;
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            ServerApp.send_amount(signedRequest.split(" "), true);
            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];


        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount01()'");
        }
        
        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "Error: Replay attack detected.\n"));

        ServerImpl.reset();
    }


    /**
     * Client 1 tries to send money to client 2 but client 1 is not registered
     */
    @Test
    public void sendAmount02()
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
        try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user1,protParam);
            privateKey1 = privateKeyEntry.getPrivateKey();
            publicKey1 = privateKeyEntry.getCertificate().getPublicKey();

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //send money from client 1 to client 2
            
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + amount + " null" + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];


        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount02'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!null!" + "Error: Sender is not registered\n"));

        ServerImpl.reset();
    }


    /**
     * Client 1 tries to send money to client 2 but client 2 is not registered
     */
    @Test
    public void sendAmount03()
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

            //send money from client 1 to client 2
            wTs1++;
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount03()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "Error: Receiver is not registered\n"));

        ServerImpl.reset();
    }
    /**
     * A client tries to send money to himself
     */
    @Test
    public void sendAmount04()
    {
        KeyStore keyStore;
        PublicKey publicKey1 = null;
        PrivateKey privateKey1 = null;
        String user1 = "client1";
        String passwd1 = "secret1";
        String request;
        String signedRequest = null;
        String response = null;
        int wTs1 = 1;
        int wTs2 = 1;
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

            //send money from client 1 to client 1
            wTs1++;
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount04'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "Error: You cannot send money to your own account\n"));

        ServerImpl.reset();
    }

    /**
     * Client 1 tries to send more money than the money that he owns
     */
    @Test
    public void sendAmount05()
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

            //send money from client 1 to client 2
            wTs1++;
            int amount = 11100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + request;

            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount05'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "Error: You don't have enough balance\n"));

        ServerImpl.reset();
    }

    /**
     * Client 1 tries to send money from another account (invalid signature)
     */
    @Test
    public void sendAmount06()
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
        try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client 1 creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd1.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user1,protParam);
            evilPrivateKey = privateKeyEntry.getPrivateKey();
            evilPublicKey = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(evilPublicKey.getEncoded()) + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(evilPrivateKey, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 2 creation
            protParam = new KeyStore.PasswordProtection(passwd2.toCharArray());
            privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user2,protParam);
            privateKey2 = privateKeyEntry.getPrivateKey();
            publicKey2 = privateKeyEntry.getCertificate().getPublicKey();
            request = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.open_account(signedRequest.split(" "), true);

            //client 1 tries to send money from client 5 to client 2
            victimPublicKey = Library.stringToPublicKey(ClientApp.getPublicKeyByID(victimClientID));

            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(victimPublicKey.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(evilPrivateKey, request) + " " + request;

            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount06()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "Error: Invalid signature\n"));

        ServerImpl.reset();
    }


    /**
     * Send amount request is corrupted
     */
    @Test
    public void sendAmount07()
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

            //send money from client 1 to client 2
            int amount = 100;
            request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            String corrupt_request = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey1.getEncoded()) + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + "123" + " " + amount + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey1, request) + " " + corrupt_request;

            response = ServerApp.send_amount(signedRequest.split(" "), true).split(" ", 2)[1];


        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'sendAmount07()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "Error: Invalid signature\n"));

        ServerImpl.reset();
    }



}
