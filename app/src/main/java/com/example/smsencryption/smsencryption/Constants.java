package com.example.smsencryption.smsencryption;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
/**
 *
 * Class to declare all the constants shared by the application in all activities
 * Created by joana on 5/10/17.
 */

public class Constants {

    private static String W = "none";

    private static String sessionKey = "";

    private static String myNonce = "";
    private static String hisNonce = "";

    private static PublicKey myPublicKey;
    private static PrivateKey myPrivateKey;

    private static PublicKey hisPublicKey;

    private static byte[] keyForExchangeKeys;

    private static String decryptionMessage = "";

    private static int numberMessages = 0;

    private static String hisContactName = "";

    private static String receiverPhoneNumber = "none";

    public static int getNumberMessages(){
        return numberMessages;
    }

    public static void setNumberMessages(int n){
        numberMessages = n;
    }

    public static void setDecryptionMessage(String message){
        decryptionMessage = message;
    }

    public static String getDecryptionMessage(){
        return decryptionMessage;
    }

    public static void setKeyForExchangeKeys(byte[] k){
        keyForExchangeKeys = k;
    }

    public static void setW(String w){ W = w;}

    public static void setMyNonce(String pin){ myNonce= pin; }

    public static void setHisNonce(String pin){ hisNonce = pin; }

    public static void setHisPublicKey(PublicKey key){
        hisPublicKey = key;
    }

    public static void setMyPublicKey(PublicKey key){
        myPublicKey = key;
    }

    public static void setMyPrivateKey(PrivateKey key){
        myPrivateKey = key;
    }

    public static byte[] getKeyForExchangeKeys(){ return keyForExchangeKeys; }

    public static PublicKey getMyPublicKey() { return myPublicKey; }

    public static PrivateKey getMyPrivateKey() { return myPrivateKey; }

    public static PublicKey getHisPublicKey(){ return hisPublicKey; }

    public static String getMyNonce(){
        return myNonce;
    }

    public static String getHisNonce(){
        return hisNonce;
    }

    public static String getW(){ return W; }

    public static String getSessionKey(){
        return sessionKey;
    }

    public static void setSessionKey(String str){
        sessionKey = str;
    }

    public static void setHisContactName(String str){
        hisContactName = str;
    }

    public static String getHisContactName(){ return hisContactName; }

    public static String getReceiverPhoneNumber(){ return receiverPhoneNumber; }

    public static void setReceiverPhoneNumber(String phone){ receiverPhoneNumber = phone; }

}
