package pt.tecnico.ulisboa.bftb.server;

import java.io.*;
import java.security.*;
import java.sql.Timestamp;
import java.time.*;
import java.util.Base64;

public class Transaction 
{
    private long _id;
    private int _amount;
    private Timestamp _requestDate;
    private PublicKey _sender;
    private PublicKey _receiver;
    private Timestamp _receiveDate;
    private byte[] _senderSignature;
    private String _sendRequest;
    private byte[] _receiverSignature;
    private String _receiveRequest;

    /***********************/
    /* Constructor Methods */
    /***********************/

    /**
     * 
     * @param transactionID
     * @param amount
     * @param sender
     * @param receiver
     * @param senderSignature
     * @param sendRequest
     */
    public Transaction(long transactionID, int amount, PublicKey sender, PublicKey receiver, byte[] senderSignature, String sendRequest)
    {
        this._id = transactionID;
        this._amount = amount;
        this._requestDate = Timestamp.from(Instant.now());
        this._sender = sender;
        this._receiver = receiver;
        this._senderSignature = senderSignature;
        this._sendRequest = sendRequest;
    }

    /**
     * 
     * @param transactionID
     * @param amount
     * @param sender
     * @param receiver
     * @param requestDate
     * @param receiveDate
     * @param senderSignature
     * @param sendRequest
     * @param receiverSignature
     * @param receiveRequest
     */
    public Transaction(long transactionID, int amount, PublicKey sender, PublicKey receiver, Timestamp requestDate, Timestamp receiveDate, byte[] senderSignature, String sendRequest, byte[] receiverSignature, String receiveRequest)
    {
        this._id = transactionID;
        this._amount = amount;
        this._requestDate = requestDate;
        this._sender = sender;
        this._receiver = receiver;
        this._receiveDate = receiveDate;
        this._senderSignature = senderSignature;
        this._sendRequest = sendRequest;
        this._receiverSignature = receiverSignature;
        this._receiveRequest = receiveRequest;
    }


    /***********************/
    /* Getters and Setters */
    /***********************/

    /**
     * 
     * @return
     */
    public long getId() {
        return _id;
    }

    /**
     * 
     * @return
     */
    public int getAmount() {
        return _amount;
    }

    /**
     * 
     * @return
     */
    public Timestamp getRequestDate() {
        return _requestDate;
    }

    /**
     * 
     * @return
     */
    public PublicKey getSender() {
        return _sender;
    }

    /**
     * 
     * @return
     */
    public PublicKey getReceiver() {
        return _receiver;
    }

    /**
     * 
     * @return
     */
    public Timestamp getReceiveDate() {
        return _receiveDate;
    }

    /**
     * 
     * @param ts
     */
    public void setReceiveDate(Timestamp ts) {
        _receiveDate = ts;
    }


    public byte[] getSenderSignature() {
        return _senderSignature;
    }

    public void setSenderSignature(byte[] _senderSignature) {
        this._senderSignature = _senderSignature;
    }

    public String getSendRequest() {
        return _sendRequest;
    }

    public void setSendRequest(String _sendRequest) {
        this._sendRequest = _sendRequest;
    }

    public byte[] getReceiverSignature() {
        return _receiverSignature;
    }

    public void setReceiverSignature(byte[] _receiverSignature) {
        this._receiverSignature = _receiverSignature;
    }

    public String getReceiveRequest() {
        return _receiveRequest;
    }

    public void setReceiveRequest(String _receiveRequest) {
        this._receiveRequest = _receiveRequest;
    }

    /********************/
    /* Auxiliar Methods */
    /********************/

    /**
     * 
     * @return
     */
    public String representation() {
        return _id + ";" +
            _amount + ";" +
            Base64.getEncoder().encodeToString(_sender.getEncoded()) + ";" +
            Base64.getEncoder().encodeToString(_receiver.getEncoded()) + ";" +
            _requestDate + ";" +
            _receiveDate + ";" +
            Base64.getEncoder().encodeToString(_senderSignature) + ";" +
            _sendRequest + ";" +
            receiverRepresentation();
    }

    private String receiverRepresentation() {
        if (_receiveDate == null)
            return null +";"+null;
        return Base64.getEncoder().encodeToString(_receiverSignature) + ";" + _receiveRequest;
    }
}