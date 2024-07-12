package pt.tecnico.ulisboa.bftb.server;

import java.io.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class Account 
{
    private int _currentBalance;
    private PublicKey _publicKey;
    private CopyOnWriteArrayList<Long> _pendingTransactions = new CopyOnWriteArrayList<>();
    private CopyOnWriteArrayList<Long> _transactionsIDs = new CopyOnWriteArrayList<>();


    /***********************/
    /* Constructor Methods */
    /***********************/

    /**
     * 
     * @param pbKey
     */
    public Account(PublicKey pbKey/*, double transactionID*/)
    {
        this._currentBalance = 10000;
        this._publicKey = pbKey;
    }

    /**
     * 
     * @param pbKey
     * @param balance
     * @param transactions
     * @param pending
     */
    public Account(PublicKey pbKey, int balance, CopyOnWriteArrayList<Long> transactions, CopyOnWriteArrayList<Long> pending)
    {
        this._publicKey = pbKey;
        this._currentBalance = balance;
        this._transactionsIDs = transactions;
        this._pendingTransactions = pending;
    }


    /***********************/
    /* Getters and Setters */
    /***********************/

    /**
     * 
     * @return
     */
    public int getBalance() {
        return _currentBalance;
    }

    /**
     * 
     * @return
     */
    public PublicKey getPublicKey() {
        return _publicKey;
    }

    /**
     * 
     * @return
     */
    public CopyOnWriteArrayList<Long> getPendingTransactions() {
        return _pendingTransactions;
    }

    /**
     * 
     * @param _pendingTransactions
     */
    public void setPendingTransactions(CopyOnWriteArrayList<Long> _pendingTransactions) {
        this._pendingTransactions = _pendingTransactions;
    }

    /**
     * 
     * @return
     */
    public CopyOnWriteArrayList<Long> getTransactionsIDs() {
        return _transactionsIDs;
    }

    /**
     * 
     * @param _transactionsIDs
     */
    public void setTransactionsIDs(CopyOnWriteArrayList<Long> _transactionsIDs) {
        this._transactionsIDs = _transactionsIDs;
    }


    /********************************/
    /* Variable Manipulator Methods */
    /********************************/
   
    /**
     * 
     * @param transactionID
     */
    public void addTransaction(long transactionID) {
        this._transactionsIDs.addIfAbsent(transactionID);
    }

    /**
     * 
     * @param amount
     */
    public void addBalance(int amount) {
        _currentBalance = _currentBalance + amount;
    }

    /**
     * 
     * @param amount
     */
    public void removeBalance(int amount) {
        if (_currentBalance < amount) 
            System.out.println("Exception on removeBalance().");
        else
            _currentBalance = _currentBalance - amount;
    }

    /**
     * 
     * @param transactionID
     */
    public void addPendingTransaction(long transactionID) {
        this._pendingTransactions.addIfAbsent(transactionID);
    }

    /**
     * 
     * @param transactionID
     */
    public void removePendingTransaction(long transactionID) {
        this._pendingTransactions.remove(transactionID);
        this._transactionsIDs.add(transactionID);
    }


    /********************/
    /* Auxiliar Methods */
    /********************/

    /**
     * 
     * @return
     */
    public String representation() {
        
        String pending = "(";
        String transactions = "(";
        for (int i=0; i < _pendingTransactions.size(); i++) {
            if (i==0)
                pending += _pendingTransactions.get(i);
            else 
                pending += "," + _pendingTransactions.get(i);
        }
        for (int i=0; i < _transactionsIDs.size(); i++) {
            if (i==0)
                transactions += _transactionsIDs.get(i);
            else 
                transactions += "," + _transactionsIDs.get(i);
        }
        pending += ")";
        transactions += ")";
        return Base64.getEncoder().encodeToString(_publicKey.getEncoded()) + ";" +
            _currentBalance + ";" +
            transactions + ";" +
            pending;
    }
}