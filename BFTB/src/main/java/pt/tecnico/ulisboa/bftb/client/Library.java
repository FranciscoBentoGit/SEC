package pt.tecnico.ulisboa.bftb.client;

import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.*;

import javax.lang.model.util.ElementScanner6;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.math.BigInteger;
import org.apache.commons.lang3.StringUtils;
 
public class Library
{
    // initialize socket and input output streams
    private List<Socket> socket = new ArrayList<Socket>();
    private List<DataOutputStream> out = new ArrayList<DataOutputStream>();
    private List<DataInputStream> in = new ArrayList<DataInputStream>();
    private List<PublicKey> serverPublicKey = new ArrayList<PublicKey>();
    private Socket socketAux = null;

    // 1-N register
    private int NUMBER_OF_REPLICAS = 4;
    private int wTs = 0;
    private ArrayList<Integer> ackList = new ArrayList<>();
    private ArrayList<Integer> validReplicas = new ArrayList<>();
    
    //private ArrayList<Integer> knownByzantine = new ArrayList<>();
    private int rID = 0;
    private HashMap<Integer, ReadingTuple> readList = new HashMap<>();
    private boolean reading = false;

    private MessageDigest messageDigest;
    private static HashMap<Integer, byte[]> hashByServer = new HashMap<>();

    /********************/
    /*  Main functions  */
    /********************/

    /**
     * 
     * @param request
     * @param signature
     * @return
     */
    public String sendAndReceive(String request, String signature, boolean isRead) {
        String reply = null;
        String[] aux = request.split(" ");
        String checkResponseSignature = null;
        String type = aux[0];
        PublicKey targetPublicKey = stringToPublicKey(aux[1]);
        int tsFromServer = 0;
        int rIDFromServer = 0;
        boolean writeQuorum = false;
        boolean isError = false;
        boolean toDecrement = false;
        HashMap<String, Integer> responsesToWrites = new HashMap<>();
        boolean readReady = false;
        
        try {    
            //loop that sends request to all replicas from port 500x to 500y
            for (int i = 0; i < validReplicas.size(); i++) {
                try {
                    out.get(validReplicas.get(i)).writeUTF(signature + " " + request);
                } catch (SocketException e) {
                    continue;
                }
            }

            for (int i = 0; i < validReplicas.size(); i++) {
                //time limit frame -- possible dead replica or not responding due to catch DOS attack
                String[] serverReply = null;
                int replicaID = validReplicas.get(i);
                try {
                    serverReply = in.get(replicaID).readUTF().split(" ", 3); // with hash :sign hash reply
                } catch (SocketTimeoutException e) {
                    print("Error: replica " + replicaID + " is not responding.");
                    if (replicaID == 3) 
                        return "Error: DOS detected.";
                    continue;
                } catch (SocketException  | EOFException seeof) {
                    print("Error: replica " + replicaID + " is dead.");
                    continue;
                }

                // here we can save all 4 replica's hash
                hashByServer.put(replicaID, serverReply[1].getBytes());

                if (readReady)
                    return reply;

                if (writeQuorum)
                    break;

                String[] signatureAndReply = serverReply[2].split("!", 5); // with hash serverReply[2]
                checkResponseSignature = signatureAndReply[0];
                if (!isRead) {
                    wTs = Integer.valueOf(aux[aux.length-2]);
                    tsFromServer = Integer.valueOf(signatureAndReply[1]);
                    reply = signatureAndReply[2];
                    if (type.equals("send_amount"))
                        reply = readSendAmount(reply);

                } else {
                    rID = Integer.valueOf(aux[aux.length-2]);
                    reading = true;
                    rIDFromServer = Integer.valueOf(signatureAndReply[1]);
                    
                    if (!signatureAndReply[2].equals("null"))
                        tsFromServer = Integer.valueOf(signatureAndReply[2]);
                    else
                        tsFromServer = 0;

                    if (signatureAndReply[4].startsWith("Error:")) {
                        type = signatureAndReply[3];
                        reply = signatureAndReply[4];
                        isError = true;
                    }
                    else {
                        type = signatureAndReply[3];
                        reply = signatureAndReply[4];
                    }
                }
                
                // verify server signature
                if (!verifySignature(serverPublicKey.get(replicaID), serverReply[1] + " " + serverReply[2], serverReply[0])) { // with hash: + " " + serverReply[2]
                    print("Error: invalid signature");
                }

                // verify signature sent by client, to guarantee freshness
                if (!signature.equals(checkResponseSignature)) {
                    print("Error: invalid response from server");
                }

                if (!isRead) {
                    if (wTs != tsFromServer)
                        continue;

                    ackList.add(tsFromServer);
                    if (responsesToWrites.containsKey(reply))
                        responsesToWrites.put(reply, responsesToWrites.get(reply) + 1);
                    else
                        responsesToWrites.put(reply, 1);
                    
                    if (ackList.size() > NUMBER_OF_REPLICAS/2 && writeQuorum == false) {
                        ackList.clear();
                        writeQuorum = true;
                    }

                } else {
                    if (rID != rIDFromServer)
                        continue;

                    String[] transactions = reply.split("!");

                    if (transactions.length > 1) { //all transactions to audit
                        if (type.equals("audit"))
                            //if the replica is malicious
                            if (verifyServerAudit(transactions, targetPublicKey, replicaID)) {
                                validReplicas.remove(i);
                                continue;
                            }

                        if (type.equals("check_account")) { //pending transactions +  all transactions that change balance
                            //if the replica is malicious
                            if (verifyServerCheckAccount(transactions, targetPublicKey, replicaID)) {
                                validReplicas.remove(i);
                                continue;
                            }
                            reply = reply.split("transactions")[0];
                        }
                    }
                    
                    ReadingTuple tuple = new ReadingTuple(tsFromServer, reply);
                    readList.put(replicaID, tuple);

                    if (readList.size() > NUMBER_OF_REPLICAS/2) {
                        ArrayList<String> highestVal = highestVal();
                        String maxTs = highestVal.get(0);
                        String value = highestVal.get(1);
                        readList.clear();
                        
                        String aux_value = value;
                        if (!isError)
                            aux_value = type + "!" + value;
                        reply = aux_value;
                        readReady = true;

                        if (type.equals("audit"))
                            reply = readAudit(aux_value.split("!"));
                        else if (type.equals("check_account"))
                            reply = readCheckAccount(aux_value.split("!"));
                        readReady = true;
                    }
                }
            }

            if (writeQuorum) {
                int max = 0;

                if (responsesToWrites.size() == 3)
                    return "Error: no quorum was achieved in writes.";

                for (HashMap.Entry<String, Integer> entry : responsesToWrites.entrySet()) {
                    if (entry.getValue() > max) {
                        max = entry.getValue();
                        reply = entry.getKey();
                    }
                }

                if (reply.startsWith("Error: "))
                    toDecrement = true;

                return reply + toDecrement;
            }  

        } catch (IOException e) {
            e.printStackTrace();
        }
        return reply;
    }

    public ArrayList<String> highestVal() {
        int highestTs_temp = -1;
        String reply = null;

        for (HashMap.Entry<Integer, ReadingTuple> entry : readList.entrySet()) {
            ReadingTuple value = entry.getValue();
            if (value != null && value.getTs() > highestTs_temp) {
                highestTs_temp = value.getTs();
                reply = value.getReply();
            }     
        }
        
        return new ArrayList<>(Arrays.asList(String.valueOf(highestTs_temp), reply));
    }

    public Boolean verifyServerAudit(String[] transactions, PublicKey targetPublicKey, int i) {
        Boolean isMalicious = false;
        for (int t = 1; t < transactions.length; t++) {
            String[] transaction = transactions[t].split(";");

            // if the target client is the sender
            if (targetPublicKey.equals(stringToPublicKey(transaction[2]))) {
                if (!verifySignature(targetPublicKey, transaction[7], transaction[6])) {
                    print("Error: malicious replica: " + i);
                    isMalicious = true;
                    continue;
                }
            }
            // if the target client is the receiver
            else if (targetPublicKey.equals(stringToPublicKey(transaction[3]))) {
                if (!verifySignature(targetPublicKey, transaction[9], transaction[8])) {
                    isMalicious = true;
                    print("Error: malicious replica: " + i);
                    continue;
                }
            }
            // if the target client isn't the sender nor the receiver
            else {
                isMalicious = true;
                print("Error: malicious replica: " + i);
                continue;                            
            }
        }  
        return isMalicious;
    }

    public Boolean verifyServerCheckAccount(String[] reply, PublicKey targetPublicKey, int serverID) {
        Boolean isMalicious = false;
        int server_balance = Integer.valueOf(reply[0]);
        int balance = 10000;
        String transactions = "";
        Boolean isTransaction = false;

        //w/ error there is no transactions to analyse
        if (reply[0].startsWith("Error"))
            return false;

        for (int i = 1; i < reply.length; i++) {
            //to avoid analysing pending transactions
            if (reply[i].equals("transaction")) {
                isTransaction = true;
                continue;
            }
            if (isTransaction) {
                transactions += reply[i];
                //if it's not the last transaction
                if (reply.length-1 != 0)
                    transactions += "!";
            }
        }
        
        String[] transactions_list = null;
        if (!transactions.equals(""))
            transactions_list = transactions.split("!");
        // checks if the transactions are corrupted

        if (transactions_list != null) {
            isMalicious = verifyServerAudit(transactions_list, targetPublicKey, serverID);
            if (!isMalicious) {
                for (int i = 0; i < transactions_list.length; i++) {
                    String[] transaction = transactions_list[i].split(";");
                    int amount = Integer.valueOf(transaction[1]);
    
                    // if the target client is the sender
                    if (targetPublicKey.equals(stringToPublicKey(transaction[2]))) {
                        balance -= amount;
                    }
                    // if the target client is the receiver
                    else {
                        balance += amount;
                    }
                }
                isMalicious = (balance==server_balance);
            }    
        }
        return isMalicious;
    }

    /**
     * 
     * @param response
     * @return
     */
    public String readSendAmount(String response) {
        String[] aux1 = response.split("\n", 2);
        if (aux1[1].equals(""))
            return response;            
        String[] aux2 = aux1[1].split(" ", 2);
        return aux1[0] + "\n" + getClientByPublicKey(aux2[0]) + " " + aux2[1];
    }

 
    /**
     * 
     * @param response
     * @return
     */
    public String readCheckAccount(String[] response) {
        String res = "";
        if (response.length > 2) {
            res = "Balance: " + response[1] + "\n";
            res += "Pending Transactions:\n";
            res += "Transaction ID\tFrom\t\tAmount\tDate\n";
            for (int i = 2; i<response.length; i++) {
                String[] request = response[i].split(";");
                res += request[0] + "\t\t" + getClientByPublicKey(request[2]) + "\t" + request[1] + "\t" + request[4].substring(0, 19) + "\n";
            }
        }
        else if (response.length == 2) {
            res = "Balance: " + response[1] + "\n";
            res += "No pending transactions.\n";
        }
        else
            res = response[0];
        return res;
    }

    /**
     * 
     * @param response
     * @return
     */
    public String readAudit(String[] response) {
        String res = "";
        if (response.length > 2) {
            res += "Completed Transactions:\n";
            res += "Transaction ID\tAmount\tFrom\t\tTo\t\tRequest Date\t\tReceive Date\n";
            for (int i = 2; i<response.length; i++) {
                String[] request = response[i].split(";");
                res += request[0] + "\t\t" + request[1] + "\t" + getClientByPublicKey(request[2]) + "\t" + getClientByPublicKey(request[3]) + "\t";
                String requestDate = request[4].substring(0, 19);
                res += requestDate;
                if (request[5].equals("null"))
                    res += "\tPending\n";
                else{
                    String receiveDate = request[5].substring(0, 19);
                    res += "\t" + receiveDate + "\n";
                }
            }
        }
        else if (response.length == 2)
            res = response[1];
        else
            res = response[0];
        return res;
    }

    
    /*************************/
    /*  Signature Functions  */
    /*************************/

    /**
     * 
     * @param pbKey
     * @param input
     * @param signature
     * @return
     */
    public Boolean verifySignature(PublicKey pbKey, String input, String signature){
        try {
            Security.addProvider(new BouncyCastleProvider());
            Signature rsaForVerify = Signature.getInstance("SHA256withRSA/PSS");
            rsaForVerify.initVerify(pbKey);
            rsaForVerify.update(input.getBytes());
            byte[] sig = Base64.getDecoder().decode(signature);
            Boolean verifies = rsaForVerify.verify(sig);
            return verifies;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }


    /**************************/
    /*  Connection Functions  */
    /**************************/

    /**
     * 
     * @param address
     * @param port
     */
    public void connect(String address, int port){
        // establish a connection
        try
        {
            socketAux = new Socket(address, port);
            socketAux.setSoTimeout(3*1000);
            socket.add(socketAux);
            
            int pos = socket.size() - 1;
 
            // sends output to the socket
            out.add(new DataOutputStream(socket.get(pos).getOutputStream()));

            // takes input from the server
            in.add(new DataInputStream(
                new BufferedInputStream(socket.get(pos).getInputStream())));
            
            serverPublicKey.add(stringToPublicKey(in.get(pos).readUTF()));
            
            validReplicas.add(validReplicas.size());

        } catch (ConnectException ce) {
            print("\n******************************************************");
            print("Connection refused with replica in port " + port + ".");
            print("******************************************************\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
 
    }

    /**
     * 
     */
    public void disconnect(){
        // close the connection
        try
        {
            for (int i = 0; i < socket.size(); i++) {
                in.get(i).close();
                out.get(i).close();
                socket.get(i).close();
            }
        }
        catch(IOException i)
        {
            System.out.println(i);
        }
    }


    /**********************/
    /* Auxiliar functions */
    /**********************/

    /**
     * 
     * @param msg
     */
    public static void print(Object msg) {
        System.out.println(msg);
    }

    public static HashMap<Integer, byte[]> getHashByServer() {
        return hashByServer;
    }
    
    public static String getClientByPublicKey(String pubKey) {
        try {
            File file = new File("client-files/publicKeyRecord.txt");
            FileReader fr = new FileReader(file);
            BufferedReader br = new BufferedReader(fr);
            int count = 1;
            String line;
            while((line=br.readLine())!= null) {
                if (line.equals(pubKey))
                    break;
                count++;
            }
            fr.close();
            
            String res = "client "+ count;
            return res;

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static PublicKey stringToPublicKey(String input) {
        try {
            byte publicKeyData[] = Base64.getDecoder().decode(input);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyData);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);    
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }
    }

    public class ReadingTuple {
        private int _ts;
        private String _reply;

        public ReadingTuple(int ts, String reply) {
            _ts = ts;
            _reply = reply;
        }

        public int getTs() {
            return _ts;
        }
        
        public String getReply() {
            return _reply;
        }
    }
}
