package pt.tecnico.ulisboa.bftb.server;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ServerApp extends ServerImpl
{
    private Socket socket = null;
    private ServerSocket server = null;

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static Certificate certificate;
    private static Signature rsaForSign;
    private static int passwdNumber;

    private Socket socketInternal = null;
    private ServerSocket serverInternal = null;

    private Socket socketS = null;
    private DataOutputStream outS = null;
    private DataInputStream inS = null;

    private Socket socketSS = null;
    private DataOutputStream outSS = null;
    private DataInputStream inSS = null;

    private static DataInputStream input = new DataInputStream(System.in);

    /**
     * 
     * @param args
     */
    public static void main(String args[])
    {
        //allow the creation of multiple replicas
        try {
            System.out.print("Insert server port: ");
            String port = input.readLine();
            while (Integer.valueOf(port) > 5003 || Integer.valueOf(port) < 5000) {
                System.out.println("Insert a valid port, from 5000 to 5003. Please try again.");
                System.out.print("Insert server port: ");
                port = input.readLine();
            }
            passwdNumber = Integer.parseInt(port) - 5000;

            setLogFilePath(passwdNumber);

            ServerApp server = new ServerApp(Integer.parseInt(port));
        } catch (IOException e) {
            e.printStackTrace();
        }   
    }

    /********************/
    /*   Main Methods   */
    /********************/

    /**
     * 
     * @param port
     */
    public ServerApp(int port)
    {
        // starts server and waits for a connection
        Security.addProvider(new BouncyCastleProvider());
        try
        {   
            // get RSA key pair
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("server-files/keystorefile.jks"), "password".toCharArray());
            String entry = "server" + String.valueOf(passwdNumber);
            String passwd = "secret" + String.valueOf(passwdNumber);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry(entry, protParam);
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            certificate = privateKeyEntry.getCertificate();
            
            server = new ServerSocket(port);
            serverInternal = new ServerSocket(port + 3000);
            
            System.out.println("Server started");
 
            System.out.println("Waiting for clients ...");

            readLogs();            
            
            while (true) {
                socket = server.accept();

                Thread t1 = new Thread() {
                    public void run() {
                        try {
                            // takes input from the client socket
                            DataInputStream in = new DataInputStream(
                                new BufferedInputStream(socket.getInputStream()));
                            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        
                            String line = "";
                            String reply = "";

                            // server sends his public key as the connection is made
                            out.writeUTF(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                            while (!line.equals("Over"))
                            {
                                line = in.readUTF();
                                String[] components = line.split(" ");
                                System.out.println(line);
                                switch(components[1]) { // signature specificrequest data.....
                                    case "open_account":
                                        reply = open_account(components, false);
                                        if (!reply.equals("isDOS"))
                                            out.writeUTF(signMessage(reply) + " " + reply);
                                        break;
                                    case "send_amount":
                                        reply = send_amount(components, false);
                                        if (!reply.equals("isDOS"))
                                            out.writeUTF(signMessage(reply) + " " + reply);
                                        break;
                                    case "receive_amount":
                                        reply = receive_amount(components, false);
                                        if (!reply.equals("isDOS"))
                                            out.writeUTF(signMessage(reply) + " " + reply);
                                        break;
                                    case "audit":
                                        reply = readCheckAccountOrAudit(components);
                                        if (!reply.equals("isDOS"))
                                            out.writeUTF(signMessage(reply) + " " + reply);
                                        break;
                                    case "check_account":
                                        reply = readCheckAccountOrAudit(components);
                                        if (!reply.equals("isDOS"))
                                            out.writeUTF(signMessage(reply) + " " + reply);
                                        break;
                                    default:
                                        out.writeUTF("wrong command");
                                        break;
                                }
                            }
                            System.out.println("Closing connection");
                
                            // close connection
                            socket.close();
                            in.close();
                        } catch (IOException e) { } //} catch (UnsupportedEncodingException u2) { } catch (IOException | NoSuchAlgorithmException e) { } 

                    }
                };

                t1.start();
            }

        } 
        catch(IOException i)
        {
            System.out.println(i);
        } catch (KeyStoreException e1) {
            e1.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (CertificateException e1) {
            e1.printStackTrace();
        } catch (UnrecoverableEntryException e1) {
            e1.printStackTrace();
        } 


    }


    /*************************/
    /*   Signature Methods   */
    /*************************/

    /**
     * 
     */
    public static void initSignature(){
        try {
            rsaForSign = Signature.getInstance("SHA256withRSA/PSS");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            rsaForSign.initSign(privateKey,random);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    
    }

    /**
     * 
     * @param txt
     * @return
     */
    public static String signMessage(String txt){
        initSignature();
        byte[] signature;
        try {
            rsaForSign.update(txt.getBytes());
            signature = rsaForSign.sign();
            return Base64.getEncoder().encodeToString(signature);
            
        } catch (SignatureException e) {
            e.printStackTrace();
            return ("Error: something happened while signing the following message: " + txt);
        }
    }

}
