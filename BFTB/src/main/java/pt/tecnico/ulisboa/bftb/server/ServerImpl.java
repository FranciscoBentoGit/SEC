package pt.tecnico.ulisboa.bftb.server;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.*;
import java.sql.Timestamp;
import java.time.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.concurrent.locks.ReentrantLock;
import java.security.MessageDigest;
import java.util.*;


public class ServerImpl
{
    // function use
    private static ConcurrentHashMap<PublicKey, Account> _accountsMap = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, Transaction> _transactionsMap = new ConcurrentHashMap<>();
    private static CopyOnWriteArrayList<String> _knownSignatures = new CopyOnWriteArrayList<>();
    private static long _lastTransactionID = 0;

    // log use
    private static String _logFilePath;
    private static long _lastLogID = 0;

    // lock initialization
    private static ReentrantLock lock = new ReentrantLock();

    // 1-N register
    private static int wTs = 0;
    private static int r = 0;
    private static ConcurrentHashMap<PublicKey, Integer> tsByClient = new ConcurrentHashMap<>(); 

    private static ConcurrentHashMap<PublicKey, String> _outputCheckAccount = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<PublicKey, String> _outputAudit = new ConcurrentHashMap<>();

    private static ConcurrentHashMap<PublicKey, Long> lastWriteOpTsByClient = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<PublicKey, String> lastHashedStringByClient = new ConcurrentHashMap<>();

    
    /********************/
    /*  Main Functions  */
    /********************/

    /**
     * 
     * @param components
     * @param isLog
     * @return
     */
    public static String open_account(String[] components, boolean isLog) //[0]sign [1]open_account [2]publicKey [3]ts [4]proof_of_work
    {
        PublicKey pbKey = stringToPublicKey(components[2]);
        wTs = Integer.valueOf(components[3]);
        
        if (isDOS(components[4], pbKey))
            return "isDOS";
        lastHashedStringByClient.put(pbKey, randomizeString());
        String hash = null;
        try {
            hash = new String(getSHA(lastHashedStringByClient.get(pbKey)));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            print(e);
        }

        if (!verifySignature(pbKey, components[1] + " " + components[2] + " " + components[3] + " " + components[4], components[0])) 
            return hash + " " + components[0] + "!" + wTs + "!" + "Error: Invalid signature.\n";

        if (isReplayAttack(components[0])) {
            print("Error: Replay attack detected.");
            return hash + " " + components[0] + "!" + wTs + "!" + "Error: Replay attack detected.\n";
        }
        
        if (_accountsMap.containsKey(pbKey)) 
            return hash + " " + components[0] + "!" + wTs + "!" + "Error: Public key already in use.\n";

        if (!tsByClient.containsKey(pbKey))
            tsByClient.put(pbKey, 0);
        if (wTs > tsByClient.get(pbKey))
            tsByClient.put(pbKey, wTs);

        Account account = new Account(pbKey);
        _accountsMap.put(pbKey, account);

        // intialize account involved for reads
        _outputAudit.put(pbKey, audit(account));
        _outputCheckAccount.put(pbKey, check_account(account));
                
        if (!isLog) {
            String request = components[0] + " " + components[1] + " " + components[2] + " " + components[3] + " " + components[4];
            writeLog(request);    
        }

        return hash + " " + components[0] + "!" + wTs + "!" + "The account was created with success.\n";
    }

    /**
     * 
     * @param components
     * @param isLog
     * @return
     */
    public static String send_amount(String[] components, boolean isLog) { //[0]sign [1]send_amount [2]senderPublicKey [3]receiverPublicKey [4]amount [5]ts [6]proof
        int amount;
        String hash = null;
        try {
            PublicKey senderPbKey = stringToPublicKey(components[2]);

            if (isDOS(components[6], senderPbKey))
                return "isDOS";
            lastHashedStringByClient.put(senderPbKey, randomizeString());
            try {
                hash = new String(getSHA(lastHashedStringByClient.get(senderPbKey)));
            } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
                print(e);
            }

            PublicKey receiverPbKey = stringToPublicKey(components[3]);
            String request = components[1] + " " + components[2] + " " + components[3] + " " + components[4] + " " + components[5] + " " + components[6];
            String signature = components[0];

            if (components[5].equals("null"))
                return hash + " " + signature + "!" + components[5] + "!" + "Error: Sender is not registered\n";

            amount = Integer.valueOf(components[4]);
            wTs = Integer.valueOf(components[5]);
    
            if(!verifySignature(senderPbKey, request, signature))
                return hash + " " + signature + "!" + wTs + "!" + "Error: Invalid signature\n";

            if (isReplayAttack(signature)) {
                print("Error: Replay attack detected.");
                return hash + " " + signature + "!" + wTs + "!" + "Error: Replay attack detected.\n";
            }

            if (!_accountsMap.containsKey(senderPbKey)) 
                return hash + " " + signature + "!" + wTs + "!" + "Error: Sender is not registered\n";

            if (!_accountsMap.containsKey(receiverPbKey))
                return hash + " " + signature + "!" + wTs + "!" + "Error: Receiver is not registered\n";
            
            if (components[2].equals(components[3]))
                return hash + " " + signature + "!" + wTs + "!" + "Error: You cannot send money to your own account\n";    
            
            if (_accountsMap.get(senderPbKey).getBalance() < amount)
                return hash + " " + signature + "!" + wTs + "!" + "Error: You don't have enough balance\n";

            if (wTs > tsByClient.get(senderPbKey))
                tsByClient.put(senderPbKey, wTs);
    

            _lastTransactionID++;

            Transaction transaction = new Transaction(_lastTransactionID, amount, senderPbKey, receiverPbKey, Base64.getDecoder().decode(signature), request);
            _transactionsMap.put(_lastTransactionID, transaction);
        
            Account sender = _accountsMap.get(senderPbKey);
            sender.removeBalance(amount);
            sender.addTransaction(_lastTransactionID);

            Account receiver = _accountsMap.get(receiverPbKey);
            receiver.addPendingTransaction(_lastTransactionID);

            // overwrite all audits again and add the new one for each account involved
            _outputAudit.put(senderPbKey, audit(sender));
            _outputAudit.put(receiverPbKey, audit(receiver));

            _outputCheckAccount.put(senderPbKey, check_account(sender));
            _outputCheckAccount.put(receiverPbKey, check_account(receiver));
        
            if (!isLog) {
                writeLog(signature + " " + request);    
            }

            return hash + " " + signature + "!" + wTs  + "!" + "The money was sent with success.\n" + Base64.getEncoder().encodeToString(receiverPbKey.getEncoded()) + " must accept the transaction.\nYour current balance is : " + _accountsMap.get(senderPbKey).getBalance() + "\n";
            
        } catch (NumberFormatException e) {
            return hash + " " + components[0] + "!" + wTs  + "!" + "The amount must be an integer.\n";
        }
    }


    /**
     * 
     * @param components
     * @param isLog
     * @return
     */
    public static String receive_amount(String[] components, boolean isLog) { //[0]sign [1]receive_amount [2]senderPublicKey [3]transaction [4]ts [5]proof
        String clientSignature = components[0];
        String request = components[1] + " " + components[2] + " " + components[3] + " " + components[4] + " " + components[5];
        PublicKey pbKey = stringToPublicKey(components[2]);

        if (isDOS(components[5], pbKey))
            return "isDOS";
        lastHashedStringByClient.put(pbKey, randomizeString());
        String hash = null;
        try {
            hash = new String(getSHA(lastHashedStringByClient.get(pbKey)));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            print(e);
        }

        if (components[4].equals("null"))
            return hash + " " + clientSignature + "!" + components[4] + "!" + "Error: You are not registered\n";

        wTs = Integer.valueOf(components[4]);

        if (!verifySignature(pbKey, request, clientSignature))
            return hash + " " + clientSignature + "!" + wTs + "!" + "Error: Invalid signature\n";
        
        if (isReplayAttack(clientSignature)) {
            print("Error: Replay attack detected.");
            return hash + " " + clientSignature + "!" + wTs + "!" + "Error: Replay attack detected.\n";
        }

        if (!_accountsMap.containsKey(pbKey))
            return hash + " " + clientSignature + "!" + wTs + "!" + "Error: You are not registered\n";

        try {
            long transactionID = Integer.valueOf(components[3]);
            Transaction transaction = _transactionsMap.get(transactionID);

            if (!_accountsMap.get(pbKey).getPendingTransactions().contains(transactionID))
                return hash + " " + clientSignature + "!" + wTs + "!" + "Error: transactionID not in pending transactions list.\n";
            
            if (wTs > tsByClient.get(pbKey))
                tsByClient.put(pbKey, wTs);

            Account receiver = _accountsMap.get(pbKey);
            receiver.addBalance(transaction.getAmount());
            receiver.removePendingTransaction(transactionID);
            _transactionsMap.get(transactionID).setReceiveDate(Timestamp.from(Instant.now()));
            _transactionsMap.get(transactionID).setReceiveRequest(request);
            _transactionsMap.get(transactionID).setReceiverSignature(Base64.getDecoder().decode(clientSignature));

            // overwrite all audits again and add the new one for each account involved
            _outputAudit.put(pbKey, audit(receiver));
            _outputCheckAccount.put(pbKey, check_account(receiver));

            _outputAudit.put(_transactionsMap.get(transactionID).getSender(), audit(_accountsMap.get(_transactionsMap.get(transactionID).getSender())));
            _outputCheckAccount.put(_transactionsMap.get(transactionID).getSender(), check_account(_accountsMap.get(_transactionsMap.get(transactionID).getSender())));


            if (!isLog) {
                writeLog(clientSignature + " " + request);    
            }

            return hash + " " + clientSignature + "!" + wTs + "!" + "Transaction " + transactionID + " was accepted.\nYour current balance is: " + _accountsMap.get(pbKey).getBalance() + "\n";
            
        } catch (Exception e) {
            print("Cannot convert '" + components[3] + "' to Integer");
            return hash + " " + components[0] + "!" + wTs + "!" + "Cannot convert '" + components[3] + "' to Integer\n";
        }
    

    }


    /**
     * 
     * @param components
     * @return
     */
    public static String check_account(Account account) {
        String res = "check_account!" + account.getBalance();
        for (int i=0; i < account.getPendingTransactions().size(); i++) {
            Transaction t = _transactionsMap.get(account.getPendingTransactions().get(i));
            res += "!" + t.representation();
        }
        return res;
    }


    /**
     * 
     * @param components
     * @return
     */
    public static String audit(Account account) {
        String res = "audit";
        if (account.getTransactionsIDs().size() > 0) {
            res += "!transactions";
            for (int i = 0; i < account.getTransactionsIDs().size(); i++) {
                res += "!" + getTransactionByID(account.getTransactionsIDs().get(i)).representation();
            }
            return res;
        }
        else
            res += "!The given account doesn't have any related transactions.\n";
        return res;
    }


    /**
     * 
     * @param components
     * @return
     */
    public static String readCheckAccountOrAudit(String[] components) {

        r = Integer.valueOf(components[4]);

        PublicKey pbKey = stringToPublicKey(components[3]);
        PublicKey pbKeyToAudit = stringToPublicKey(components[2]);

        if (isDOS(components[5], pbKey))
            return "isDOS";
        lastHashedStringByClient.put(pbKey, randomizeString());
        String hash = null;
        try {
            hash = new String(getSHA(lastHashedStringByClient.get(pbKey)));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            print(e);
        }

        if (!verifySignature(pbKey, components[1] + " " + components[2] + " " + components[3] + " " + components[4] + " " + components[5], components[0])) 
            return hash + " " + components[0] + "!" + r + "!" + tsByClient.get(pbKeyToAudit) + "!" + components[1] + "!" + "Error: Invalid signature.\n";

        if (isReplayAttack(components[0])) {
            print("Error: Replay attack detected.");
            return hash + " " + components[0] + "!" + r + "!" + tsByClient.get(pbKeyToAudit) + "!" + components[1] + "!" + "Error: Replay attack detected.\n";
        }

        if (!_accountsMap.containsKey(pbKey))
            return hash + " " + components[0] + "!" + r + "!" + null + "!"  + components[1] + "!" + "Error: You are not registered\n";

        if (!_accountsMap.containsKey(pbKeyToAudit))
            return hash + " " + components[0] + "!" + r + "!" + null + "!"  + components[1] + "!" + "Error: This client is not registered\n";

        String res = "";
        if (components[1].equals("audit"))
            res = r + "!" + tsByClient.get(pbKeyToAudit) + "!" + _outputAudit.get(pbKeyToAudit); //replica_rID + replica_ts + audit
        else if (components[1].equals("check_account"))
            res = r + "!" + tsByClient.get(pbKeyToAudit) + "!" + _outputCheckAccount.get(pbKeyToAudit) + "!" + auditWoPendings(pbKeyToAudit); //replica_rID + replica_ts + audit

        return hash + " " + components[0] + "!" + res;
    }

    public static String auditWoPendings(PublicKey pbKeyToAudit) {
        String[] aux = audit(getAccountByPublicKey(pbKeyToAudit)).split("!",3);
        String res = "transactions";
        if (res.equals(aux[1]))
            res += "!" + aux[2];
        return res;
    }
 

    /*******************/
    /*  Log Functions  */
    /*******************/

    /**
     * 
     * @param request
     */
    public static void writeLog(String request) {
        FileWriter fw = null;
        BufferedWriter bw = null;
        PrintWriter pw = null;

        try {
            // 'true' implies append
            fw = new FileWriter(_logFilePath, true);
            bw = new BufferedWriter(fw);
            pw = new PrintWriter(bw);

            _lastLogID++;
            String log = _lastLogID + " " + request;

            pw.println(log);
            pw.flush();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                pw.close();
                bw.close();
                fw.close();
            } catch (IOException io) {// can't do anything }
            }

        }

    }


    /**
     * 
     * @throws FileNotFoundException
     * @throws IOException
     */
    public void readLogs() throws FileNotFoundException, IOException {
        File file = new File(_logFilePath);
        if (!file.exists())
            file.createNewFile();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                new FileInputStream(_logFilePath), StandardCharsets.UTF_8));) {

            String line;
            
            while ((line = br.readLine()) != null) {
                print(line);
                String[] components = line.split(" ", 2);
                String[] request = components[1].split(" ");

                switch(request[1]) {
                    case "open_account":
                        open_account(request, true);
                        break;
                    case "send_amount":
                        send_amount(request, true);
                        break;
                    case "receive_amount":
                        receive_amount(request, true);
                        break;
                    default:
                        print("An error occurred while reading logs.");
                    return;
                }
                _lastLogID = Long.valueOf(components[0]);
            }
        }

        print("Finished reading logs.");

    }


    /************************/
    /*  Security Functions  */
    /************************/

    /**
     * 
     * @param pbKey
     * @param input
     * @param signature
     * @return
     */
    public static Boolean verifySignature(PublicKey pbKey,String input,String signature){
        try {
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


    /**
     * 
     * @param signature
     * @return
     */
    public static Boolean isReplayAttack(String signature) {
        //crtical section
        lock.lock();
        try {
            if(_knownSignatures.contains(signature))
                return true;
            _knownSignatures.add(signature);
        } finally {
            lock.unlock();
        }
        return false;
    }

    public static String randomizeString() {
        //String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
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

    public static boolean isDOS(String proof, PublicKey pbKey) {
        if (lastHashedStringByClient.containsKey(pbKey)) {
            if (!proof.equals("empty")) {
                String proof_of_work[] = proof.split("-");
                boolean found = false;
                for (int i = 0; i < proof_of_work.length; i++) {
                    if (proof_of_work[i].equals(lastHashedStringByClient.get(pbKey)))
                        found = true;
                }

                if (!found)
                    return true;
                else
                    return false;
            }
        }
        return false;
    }


    /************************/
    /*     Aux Functions    */
    /************************/

    public static void print(Object text) {
        System.out.println(text);
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


    public static ConcurrentHashMap<PublicKey, Account> get_accountsMap() {
        return _accountsMap;
    }


    public static void reset() {
        _accountsMap = new ConcurrentHashMap<>();
        _transactionsMap = new ConcurrentHashMap<>();
        _knownSignatures = new CopyOnWriteArrayList<>();
        _lastTransactionID = 0;
        _lastLogID = 0;
        wTs = 0;
        r = 0;
        tsByClient = new ConcurrentHashMap<>();
        _outputCheckAccount = new ConcurrentHashMap<>();
        _outputAudit = new ConcurrentHashMap<>();
        lastWriteOpTsByClient = new ConcurrentHashMap<>();
    }


    public static Transaction getTransactionByID(long id) {
        return _transactionsMap.get(id);
    }


    public static Account getAccountByPublicKey(PublicKey publicKey) {
        return _accountsMap.get(publicKey);
    }

    public static void setLogFilePath(int number) {
        _logFilePath = "server-files/log" + number + ".txt";
    }


}