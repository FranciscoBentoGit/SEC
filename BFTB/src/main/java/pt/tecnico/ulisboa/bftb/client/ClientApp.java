package pt.tecnico.ulisboa.bftb.client;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.swing.TransferHandler.TransferSupport;

import java.io.*;
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
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.MessageDigest;

public class ClientApp {
    public static Library library = new Library();
    
    private static DataInputStream input = new DataInputStream(System.in);
    private static DataInputStream in = null;
    
    private static boolean connected;
    private static boolean keyPairSelected = false;
    
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static Certificate certificate;

    private static int wTs = 0;
    private static int rID = 0;

    /**
     * 
     * @param args
     */
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        while(!keyPairSelected){
            selectKeyPair();
        }
        connect();
        while (connected){
            mainMenu();
        }
        library.disconnect();
    }


    /********************/
    /*   Main Methods   */
    /********************/

    /**
     * 
     */
    public static void openAccount() {
        drawBox("Open Account");
        print("\n=========Server Response=========");
        wTs += 1;
        String input = "open_account" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + wTs + " " + proofOfWork(library.getHashByServer());

        String reply = library.sendAndReceive(input, signMessage(privateKey, input), false);
        if (reply.split("\n").length == 2) {
            if (reply.split("\n")[1].equals("true"))
                wTs -= 1;
        }
        print(reply.split("\n")[0]);
    }
    
    /**
     * 
     */
    public static void sendAmount() {
        drawBox("Send Amount");
        
        int clientID = getClientID();
        if (clientID == -1)
            return;
        String receiverPublicKey = getPublicKeyByID(clientID);
        print("Please now choose the amount to send to client number " + clientID);

        try {
            String amount = input.readLine();
            if (evaluateInput(amount))
                return;
            wTs += 1;
            String finalInput = "send_amount" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + receiverPublicKey + " " + amount + " " + wTs + " " + proofOfWork(library.getHashByServer());;
            print("\n=========Server Response=========");

            String reply = library.sendAndReceive(finalInput, signMessage(privateKey, finalInput), false);
            if (reply.split("\n").length == 2) {
                if (reply.split("\n")[1].equals("true"))
                    wTs -= 1;
            }
            print(reply.split("\n")[0]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 
     */
    public static void receiveAmount() {
        drawBox("Receive Amount");

        print("Insert transation ID ");
        String transactionID;
        try {
            transactionID = input.readLine();
            if (evaluateInput(transactionID))
                return;
            wTs += 1;
            String finalInput = "receive_amount" + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + transactionID + " " + wTs + " " + proofOfWork(library.getHashByServer());;
            print("\n=========Server Response=========");

            String reply = library.sendAndReceive(finalInput, signMessage(privateKey, finalInput), false);
            
            if (reply.split("\n").length == 2) {
                if (reply.split("\n")[1].equals("true"))
                    wTs -= 1;
            }
            print(reply.split("\n")[0]);
        } catch (IOException e) {
            e.printStackTrace();
        }
        
    }

    /**
     * 
     */
    public static void checkAccount() {
        drawBox("Check Account");
        
        int clientID = getClientID();
        if (clientID == -1)
            return;
        String pbKey = getPublicKeyByID(clientID);
        print("Selected client " + clientID);
        
        rID += 1;
        String finalInput = "check_account" + " " + pbKey + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + rID + " " + proofOfWork(library.getHashByServer());
        print("\n=========Server Response=========");
        print(library.sendAndReceive(finalInput, signMessage(privateKey, finalInput), true));
    }

    /**
     * 
     */
    public static void audit() {
        drawBox("Audit Account");

        int clientID = getClientID();
        if (clientID == -1)
            return;
        String pbKey = getPublicKeyByID(clientID);
        print("Selected client " + clientID);
        
        rID += 1;
        String finalInput = "audit" + " " + pbKey  + " " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + " " + rID + " " + proofOfWork(library.getHashByServer());
        print("\n=========Server Response=========");
        print(library.sendAndReceive(finalInput, signMessage(privateKey, finalInput), true));
    }

    public static String proofOfWork(HashMap<Integer, byte[]> map) {
        String possible = randomizeString();
        String allStrings = "";
        for (HashMap.Entry<Integer, byte[]> entry : map.entrySet()) {
            boolean found = false;
            while (!found) {
                try {
                    String eV = new String(entry.getValue());
                    String hV = new String(getSHA(possible));
                    if (!eV.equals(hV))
                        possible = randomizeString();
                    else {
                        if (entry.getKey() != 3)
                            allStrings += possible + "-";
                        else
                            allStrings += possible;
                        found = true;
                    }
                } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
                    print(e);
                }
            }
        }
        if (allStrings.equals(""))
            allStrings = "empty";

        return allStrings;
    }

    public static String randomizeString() {
        String alphabet = "01";
        StringBuilder sb = new StringBuilder();

        // create an object of Random class
        Random random = new Random();
        int length = 2;

        for(int i = 0; i < length; i++) {
            int index = random.nextInt(alphabet.length());
            char randomChar = alphabet.charAt(index);
            sb.append(randomChar);
        }

        return sb.toString();
    }

    public static byte[] getSHA(String clearText) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-256"); 
		md.update(clearText.getBytes("UTF-8"));
		return md.digest();
	}


    /**************************/
    /*   Connection Methods   */
    /**************************/

    /**
     * 
     */
    public static void connect() {
        // port number for simplicity with password to access keystore
        for (int i = 5000; i <= 5003; i++)
            library.connect("127.0.0.1", i); 
        connected = true;
    }


    /*************************/
    /*   Signature Methods   */
    /*************************/

    /**
     * 
     */
    public static Signature initSignature(PrivateKey privKey){
        try {
            Signature sig = Signature.getInstance("SHA256withRSA/PSS");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            sig.initSign(privKey,random);
            return sig;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 
     * @param txt
     * @return
     */
    public static String signMessage(PrivateKey privKey, String txt){
        Signature sig = initSignature(privKey);
        byte[] signature;
        try {
            sig.update(txt.getBytes());
            signature = sig.sign();
            return Base64.getEncoder().encodeToString(signature);
            
        } catch (SignatureException e) {
            e.printStackTrace();
            return ("Error: something happened while signing the following message: " + txt);
        }
    }



    /*************************/
    /*  RSA KeyPair Methods  */
    /*************************/

    /**
     * 
     */
    public static void selectKeyPair(){
    
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("client-files/keystorefile.jks"),"password".toCharArray());
            
            print("Between 1 and " + getPublicKeys().size() + ", select a Pair of Public/Private Keys: ");
            String user = input.readLine();
            keyPairSelected = checkPassword(user, keyStore);

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e1) {
            e1.printStackTrace();
        }
    }

    /**
     * 
     * @param keyStore
     * @param client
     * @param passwd
     */
    public static boolean readEntry(KeyStore keyStore,String client, String passwd) {
        try {
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(passwd.toCharArray());
            PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry)keyStore.getEntry(client,protParam);
            privateKey = privateKeyEntry.getPrivateKey();
            publicKey = privateKeyEntry.getCertificate().getPublicKey();
            certificate = privateKeyEntry.getCertificate();
            return true;
        
        } catch (Exception e) {
            //too many exceptions we can't handle, so brute force catch
            print("Invalid access to keystore. Please try again.");
            return false;
        }
        
    }


    /**********************/
    /*  Auxiliar Methods  */
    /**********************/

    /**
     * Display menu graphics
     */
    public static void mainMenu() {
        
        print("=================================");
        print("|      BFTB MENU SELECTION      |");
        print("=================================");
        print("| Options:                      |");
        print("|        1. Open Account        |");
        print("|        2. Send Amount         |");
        print("|        3. Receive Amount      |");
        print("|        4. Check Account       |");
        print("|        5. Audit Account       |");
        print("|        0. Disconnect          |");
        print("=================================\n\n");

        print("Select option: ");
        try {
            String action = input.readLine();
            switch (action) {
                case "0":
                    connected = false;
                    return;
                case "1":
                    openAccount();
                    break;
                case "2":
                    sendAmount();
                    break;
                case "3":
                    receiveAmount();
                    break;
                case "4":
                    checkAccount();
                    break;
                case "5":
                    audit();
                    break;
                default:
                    print("Invalid selection");
                    break;
            }
        } catch (IOException e) {

            e.printStackTrace();
        }

    }

    /**
     * 
     * @param title
     */
    public static void drawBox(String title) {
        int padding1 = (31 - title.length())/2;
        int padding2 = padding1;
        if ((31-title.length())%2 == 1)
            padding1 += 1;
        String res = "=================================\n";
        
        res += "|" + addPadding(padding1) + title + addPadding(padding2) + "|\n";
        res += "=================================\n";
        res += "To disconnect type Disconnect\n";
    
        print(res);
    }

    /**
     * 
     * @param padding
     * @return
     */
    private static String addPadding(int padding) {
        String res = "";
        for (int i = 0; i < padding; i++)
            res += " ";
        return res;
    }

    /**
     * 
     * @param input
     * @return
     */
    public static boolean evaluateInput(String input) {
        if (GoBack(input) || checkDisconnect(input))
            return true;
        return false;
    }

    /**
     * 
     * @param string
     * @return
     */
    public static boolean GoBack(String string) {
        if (string.toLowerCase().equals("back")) {
            return true;
        }
        return false;
    }

    /**
     * 
     * @param string
     * @return
     */
    public static boolean checkDisconnect(String string) {
        if (string.toLowerCase().equals("disconnect")) {
            connected = false;
            return true;
        }
        return false;
    }

    /**
     * 
     * @param username
     * @return
     * @throws IOException
     */
    public static boolean checkPassword(String user, KeyStore keyStore) {
        try {
            System.out.print("Insert your password: ");
            String passwd = input.readLine();
            if (readEntry(keyStore, "client"+user, passwd))
                return true;
            return false;

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 
     * @param sb
     * @return
     */
    public static int getClientID() {
        Boolean validSelection = false;
        String chosenClient;
        ArrayList<String> pubKeys = getPublicKeys();
        while(!validSelection) {
            print("Please choose a client, from number 1 to " + String.valueOf(pubKeys.size()));
            try {
                chosenClient = input.readLine();
                if (evaluateInput(chosenClient))
                    break;
                else if (Integer.parseInt(chosenClient) > 0 && Integer.parseInt(chosenClient) <= pubKeys.size()) {
                    validSelection = true;
                    return Integer.valueOf(chosenClient);
                }
                print("Invalid selection");
            } catch (IOException i) {
                i.printStackTrace();
            } catch (NumberFormatException e) {
                print("Invalid input.\n");
            }
            
        }
        // it will never reach this line
        return -1;
    }

    /**
     * 
     * @return
     */
    public static ArrayList<String> getPublicKeys() {
        try {
            File file = new File("client-files/publicKeyRecord.txt");
            FileReader fr = new FileReader(file);
            BufferedReader br = new BufferedReader(fr);
            ArrayList<String> pubKeys = new ArrayList<>();
            
            String line;
            while((line=br.readLine())!= null)
                pubKeys.add(line);
            fr.close();
            
            return pubKeys;
        } catch (IOException e1) {
            e1.printStackTrace();
            return null;
        }
    }

    /**
     * 
     * @param clientID
     * @return
     */
    public static String getPublicKeyByID(int clientID) {
        ArrayList<String> pubKeys = getPublicKeys();
        if (clientID < 1 || clientID > pubKeys.size())
            return "Error: invalid input at 'getPubliKeyByID()";
        return pubKeys.get(clientID-1);
    }


    /**
     * 
     * @param text
     */
    public static void print(Object text) {
        System.out.println(text);
    }

}