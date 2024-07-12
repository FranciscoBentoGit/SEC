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
public class TestReceiveAmount
{

    /**
     * Accept money with success
     */
    @Test
    public void receiveAmount00()
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

            //receive money with success
            wTs2++;
            request = "receive_amount" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + transactionID + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            response = ServerApp.receive_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'receiveAmount00()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs2 + "!" + "Transaction " + transactionID + " was accepted.\nYour current balance is: " + ServerImpl.get_accountsMap().get(publicKey2).getBalance() + "\n"));

        ServerImpl.reset();
    }


    /**
     * Replay attack on receive amount
     */
    @Test
    public void receiveAmount01()
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

            //tries to receive money
            wTs2++;
            request = "receive_amount" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + transactionID + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + request;
            ServerApp.receive_amount(signedRequest.split(" "), true);
            response = ServerApp.receive_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'receiveAmount01()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs2 + "!" + "Error: Replay attack detected.\n"));

        ServerImpl.reset();
    }


    /**
     * Client is not registered
     */
    @Test
    public void receiveAmount02()
    {
        KeyStore keyStore;
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        String user = "client1";
        String passwd = "secret1";
        String request;
        String signedRequest = null;
        String response = null;
        int transactionID = 1;
        int wTs1 = 1;
        int wTs2 = 1;
        try {
            Security.addProvider(new BouncyCastleProvider());

            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());

            //client creation
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(user,protParam);
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();

            //tries to receive money
            request = "receive_amount" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + transactionID + " null"  + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey, request) + " " + request;
            response = ServerApp.receive_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'receiveAmount02()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!null!" + "Error: You are not registered\n"));

        ServerImpl.reset();
    }


    /**
     * Try to receive amount with incompatible signature-public key
     * in this case we will use client 1 both as a 'sender' and an 'attacker'
     */
    @Test
    public void receiveAmount03()
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

            //attacker tries to force receive money
            request = "receive_amount" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + transactionID + " " + wTs1 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            PrivateKey evilPrivateKey = privateKey1;
            signedRequest = ClientApp.signMessage(evilPrivateKey, request) + " " + request;
            response = ServerApp.receive_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'receiveAmount03()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs1 + "!" + "Error: Invalid signature\n"));

        ServerImpl.reset();
    }


    /**
     * Receive amount request is corrupted
     */
    @Test
    public void receiveAmount04()
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

            //receive money with success
            wTs2++;
            request = "receive_amount" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + transactionID + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            String corrupt_request = "receive_amount" + " " + Base64.getEncoder().encodeToString(publicKey2.getEncoded()) + " " + transactionID + "corruptedRequest" + " " + wTs2 + " " + ClientApp.proofOfWork(ClientApp.library.getHashByServer());
            signedRequest = ClientApp.signMessage(privateKey2, request) + " " + corrupt_request;
            response = ServerApp.receive_amount(signedRequest.split(" "), true).split(" ", 2)[1];

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | IOException e1) {
            e1.printStackTrace();
            System.out.println("Something happened in 'receiveAmount04()'");
        }

        assertTrue(response.equals(signedRequest.split(" ")[0] + "!" + wTs2 + "!" + "Error: Invalid signature\n"));

        ServerImpl.reset();
    }

}
