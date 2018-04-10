package com.example.smsencryption.smsencryption;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Telephony;
import android.telephony.SmsManager;
import android.telephony.SmsMessage;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.Toast;

import com.example.smsencryption.smsencryption.database.SMSEncryptionContract;
import com.example.smsencryption.smsencryption.database.SMSEncryptionDbHelper;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * Created by joana on 4/16/17.
 *
 * Class called on every receive of a message
 */

public class SmsReceiver extends BroadcastReceiver{

    private String infoToDecrypt = "";
    private String raw = "";
    private boolean sessionErrorKey = false;
    private String originatingPhoneNumber = "";
    private String contactName = "default";
    private String errorReason = "";

    String SENT_SMS_FLAG = "SENT_SMS_FLAG";
    private String PRIVATE_KEY_FILE = "privatekey.txt";

    @Override
    public void onReceive(Context context, Intent intent) {

        Bundle bundle = intent.getExtras();
        SmsMessage[] msgs = null;
        String str = "";

        String action = intent.getAction();
        Log.i("Receiver", "Broadcast received: " + action);

        if (action.equals("my.action.string")){
            Constants.setHisContactName(intent.getExtras().getString("contactname"));
        }

        if (action.equals("sendReceiverPhone")){
            Log.i("I:::::", intent.getExtras().getString("receiverphonenumber"));
            Constants.setReceiverPhoneNumber(intent.getExtras().getString("receiverphonenumber"));
        }

        if (bundle != null) {
            //---retrieve the SMS message received---
            Object[] pdus = (Object[]) bundle.get("pdus");

            // boolean firstStep =(boolean) bundle.get("FIRST_STEP_SESSION_KEY");
            if (pdus != null) {
                msgs = new SmsMessage[pdus.length];

                if (msgs != null) {
                    for (int i = 0; i < msgs.length; i++) {

                        //this has to be only for android versions < 19
                        if (Build.VERSION.SDK_INT < 19) {
                            msgs[i] = SmsMessage.createFromPdu((byte[]) pdus[i]);
                        } else {
                            //check if this works because this is only for the case sdk >=19
                            msgs = Telephony.Sms.Intents.getMessagesFromIntent(intent);
                        }

                        raw += msgs[i].getMessageBody();
                        originatingPhoneNumber = msgs[i].getOriginatingAddress();

                        Log.i("I: ", contactName);

                        str += "SMS from " + msgs[i].getOriginatingAddress();
                        str += " :";
                        str += msgs[i].getMessageBody().toString();
                        str += "\n";
                    }
                }
            }

            Toast.makeText(context, str, Toast.LENGTH_SHORT).show();
        }

        if (!raw.equals("")) {

            if (raw.contains(":")) {

                String[] arr = raw.split(":");
                if (arr != null) {
                    String receivedMessage = arr[0];

                    if (arr.length > 1) {

                        String protocolId = arr[1];

                        int stepProtocol = 0;

                        if (arr.length > 2)
                            stepProtocol = Integer.parseInt(arr[2]);

                        if (protocolId != null) {
                            if (protocolId.compareTo("P") == 0) {
                                //run the protocol for public key exchange
                                switch (stepProtocol) {
                                    case 0:

                                        Log.i("I:","P:0: Setting the initial nonce value of Na to:"+ receivedMessage);

                                        Constants.setHisNonce(receivedMessage);
                                        Utils u = new Utils();
                                        String myNonce = u.generateNonce();
                                        Constants.setMyNonce(myNonce);

                                        Log.i("I:","P:0: generate me a nonce value (Nb):"+ Constants.getMyNonce());

                                        try {

                                            SMSEncryptionDbHelper mDbHelperUpdate = new SMSEncryptionDbHelper(context);
                                            SQLiteDatabase dbu = mDbHelperUpdate.getReadableDatabase();

                                            String[] projection = {
                                                    SMSEncryptionContract.Directory._ID,
                                                    SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                    SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                    SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                    SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                    SMSEncryptionContract.Directory.COLUMN_SESSION_KEY

                                            };

                                            String selection = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                            String[] selectionArgs = { originatingPhoneNumber };

                                            Cursor cursorUpdate = dbu.query(
                                                    SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                    projection,                               // The columns to return
                                                    selection,                                // The columns for the WHERE clause
                                                    selectionArgs,                            // The values for the WHERE clause
                                                    null,                                     // don't group the rows
                                                    null,                                     // don't filter by row groups
                                                    null                                      // The sort order
                                            );

                                            List userIds = new ArrayList<>();
                                            List ltkList = new ArrayList<>();

                                            while(cursorUpdate.moveToNext()) {
                                                long userId = cursorUpdate.getLong(
                                                        cursorUpdate.getColumnIndexOrThrow(SMSEncryptionContract.Directory._ID));
                                                userIds.add(userId);

                                                String ltk = cursorUpdate.getString(
                                                        cursorUpdate.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY));
                                                ltkList.add(ltk);
                                            }
                                            cursorUpdate.close();

                                            if (dbu!=null){
                                                dbu.close();
                                            }


                                            if (userIds.size()>0){

                                                Log.i("I:","P:0: Since the user is already registered, set my long term key from db :"+ ltkList.get(0).toString());
                                                //use this long term key obtained from db
                                                Constants.setW(ltkList.get(0).toString());

                                                //obtain my public key from db
                                                TelephonyManager tMgr = (TelephonyManager)context.getSystemService(Context.TELEPHONY_SERVICE);
                                                String myPhoneNumber = tMgr.getLine1Number();

                                                SMSEncryptionDbHelper mDbHelperMyPK = new SMSEncryptionDbHelper(context);

                                                SQLiteDatabase dbpk = mDbHelperMyPK.getReadableDatabase();

                                                // Check if the sender is already registered

                                                String[] projectionpk = {
                                                        SMSEncryptionContract.Directory._ID,
                                                        SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                        SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                        SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                        SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                        SMSEncryptionContract.Directory.COLUMN_SESSION_KEY

                                                };

                                                // Filter results WHERE "title" = 'My Title'
                                                String selectionpk = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                String[] selectionArgspk = { myPhoneNumber };

                                                Cursor cursorpk = dbpk.query(
                                                        SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                        projectionpk,                               // The columns to return
                                                        selectionpk,                                // The columns for the WHERE clause
                                                        selectionArgspk,                            // The values for the WHERE clause
                                                        null,                                     // don't group the rows
                                                        null,                                     // don't filter by row groups
                                                        null                                      // The sort order
                                                );

                                                List mypkList = new ArrayList<>();

                                                while(cursorpk.moveToNext()) {
                                                    String mypk = cursorpk.getString(
                                                            cursorpk.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY));
                                                    mypkList.add(mypk);

                                                    Log.i("I:", "P:0: My public key (Bob) from db is:"+ mypk);
                                                }
                                                cursorpk.close();

                                                byte[] bytesMyPublicKey = Hex.decodeHex(mypkList.get(0).toString().toCharArray());

                                                PublicKey myPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytesMyPublicKey));

                                                Constants.setMyPublicKey(myPublicKey);

                                                Log.i("I:", "P:0: Since you are establishing the public key exchange protocol, " +
                                                        "delete the messages and update the session key to none");

                                                ContentValues valuesSK = new ContentValues();

                                                valuesSK.put(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY, "none");

                                                String selectionUpdateSK = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                String[] selectionArgsUpdateSK = { originatingPhoneNumber };

                                                int count = dbpk.update(
                                                        SMSEncryptionContract.Directory.TABLE_NAME,
                                                        valuesSK,
                                                        selectionUpdateSK,
                                                        selectionArgsUpdateSK);

                                                //delete the conversation from the message table from this user in my db
                                                SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);
                                                SQLiteDatabase db = mDbHelper.getReadableDatabase();

                                                int countDelete = db.delete(
                                                        SMSEncryptionContract.Messages.TABLE_NAME,
                                                        SMSEncryptionContract.Messages.COLUMN_RECEIVER_PHONENUMBER + "="+ originatingPhoneNumber +
                                                                " OR "+ SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER + "=" +
                                                                originatingPhoneNumber,
                                                        null
                                                );

                                                if (dbpk!=null){
                                                    dbpk.close();
                                                }

                                                if (db!=null){
                                                    db.close();
                                                }

                                            }

                                            byte[] bytesMyPublicKey = Constants.getMyPublicKey().getEncoded();
                                            byte[] bytesHisNonce = Hex.decodeHex(Constants.getHisNonce().toCharArray());
                                            byte[] firstPartWithoutEnc = new byte[bytesHisNonce.length + bytesMyPublicKey.length];

                                            System.arraycopy(bytesHisNonce, 0, firstPartWithoutEnc, 0, bytesHisNonce.length);
                                            System.arraycopy(bytesMyPublicKey, 0, firstPartWithoutEnc, bytesHisNonce.length, bytesMyPublicKey.length);

                                            Log.i("I:", "P:0: his nonce to generate the salt:"+ Constants.getHisNonce());
                                            Log.i("I:", "P:0: my nonce to generate the salt:"+ Constants.getMyNonce());
                                            Log.i("I:", "P:0: W to generate the salt:"+ Constants.getW());

                                            byte[] salt = generateHashFromNonces(Constants.getHisNonce(), Constants.getMyNonce());
                                            String strSalt = new String(Hex.encodeHex(salt));

                                            Log.i("I:", "P:0: Salt:"+ strSalt);

                                            byte[] keyForExchangeKeys = u.deriveKey(Constants.getW(), salt, 1, 128);

                                            Constants.setKeyForExchangeKeys(keyForExchangeKeys);

                                            String strKeyForExchange = new String(Hex.encodeHex(keyForExchangeKeys));

                                            Log.i("I:", "P:0: Key for exchanging the keys:"+ strKeyForExchange);

                                            String encryptedStringFirstPart = encryptSymmetric(firstPartWithoutEnc, keyForExchangeKeys);

                                            String finalStringToSend = Constants.getMyNonce() + encryptedStringFirstPart + ":P:1";

                                            Log.i("I:", "P:0: Final string to be sent:" + finalStringToSend);

                                            //clear the variables to be reused on next transmission
                                            Constants.setNumberMessages(0);
                                            Constants.setDecryptionMessage("");

                                            SmsManager smsManager = SmsManager.getDefault();

                                            PendingIntent sentIntent = PendingIntent.getBroadcast(context, 0,
                                                    intent, 0);
                                            context.getApplicationContext().registerReceiver(
                                                    new SmsReceiver(),
                                                    new IntentFilter(SENT_SMS_FLAG));

                                            if (finalStringToSend.length() > 160) {

                                                ArrayList<String> parts = u.divideMessageManyParts(finalStringToSend);

                                                for (int i = 0; i < parts.size() - 1; i++) {
                                                    parts.set(i, parts.get(i) + ":P:1");
                                                }

                                                //At the beginning sending an indicator for the quantity of msgs to be sent
                                                //(e.g. if there are 4 messages: 4*---- message---)
                                                for (int j = 0; j < parts.size(); j++) {
                                                    parts.set(j, parts.size() + "*" + parts.get(j));
                                                }
                                                //sending the messages to the recipient: Alice
                                                for (int k = 0; k < parts.size(); k++) {
                                                    smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                            parts.get(k), sentIntent, null);
                                                }
                                            } else {
                                                smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                        finalStringToSend, sentIntent, null);
                                            }

                                        } catch (Exception e) {
                                            e.printStackTrace();
                                            sessionErrorKey = true;
                                            errorReason = e.getMessage();
                                        }
                                        break;
                                    case 1:
                                        try {

                                            //When alice receives the encrypted data first step
                                            if (arr.length > 2) {

                                                String[] arrSplit1 = arr[0].split("\\*");

                                                Constants.setNumberMessages(Constants.getNumberMessages() + 1);
                                                Constants.setDecryptionMessage(Constants.getDecryptionMessage() + arrSplit1[1]);

                                                if (Integer.parseInt(arrSplit1[0]) == Constants.getNumberMessages()) {

                                                    infoToDecrypt = Constants.getDecryptionMessage();

                                                    if (!infoToDecrypt.isEmpty()) {

                                                        //check if the W has already been inserted before in the db

                                                        SMSEncryptionDbHelper mDbHelperUpdate = new SMSEncryptionDbHelper(context);

                                                        SQLiteDatabase dbu = mDbHelperUpdate.getReadableDatabase();

                                                        // Check if the sender is already registered

                                                        String[] projectionUpdateLTK = {
                                                                SMSEncryptionContract.Directory._ID,
                                                                SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                                SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                                SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                                SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                                SMSEncryptionContract.Directory.COLUMN_SESSION_KEY

                                                        };

                                                        // Filter results WHERE "title" = 'My Title'
                                                        String selectionUpdateLTK = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                        String[] selectionArgsUpdateLTK = { originatingPhoneNumber };

                                                        Cursor cursorUpdate = dbu.query(
                                                                SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                                projectionUpdateLTK,                               // The columns to return
                                                                selectionUpdateLTK,                                // The columns for the WHERE clause
                                                                selectionArgsUpdateLTK,                            // The values for the WHERE clause
                                                                null,                                     // don't group the rows
                                                                null,                                     // don't filter by row groups
                                                                null                                      // The sort order
                                                        );

                                                        List ltkList = new ArrayList<>();

                                                        while(cursorUpdate.moveToNext()) {
                                                            String ltk = cursorUpdate.getString(
                                                                    cursorUpdate.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY));
                                                            ltkList.add(ltk);
                                                        }
                                                        cursorUpdate.close();

                                                        if (dbu!=null){
                                                            dbu.close();
                                                        }

                                                        if (ltkList.size()>0) {

                                                            Log.i("I:", "P:1: W from database is:"+ ltkList.get(0).toString());
                                                            //use this long term key obtained from db
                                                            Constants.setW(ltkList.get(0).toString());
                                                        }

                                                        Log.i("I:","P:1: about to calculate the key for exchanging keys in Alice side");

                                                        Log.i("I:", "First of all, the info to decrypt is:"+infoToDecrypt);

                                                        byte[] receivedBytes = Hex.decodeHex(infoToDecrypt.toCharArray());
                                                        byte[] hisNoncePart = Arrays.copyOfRange(receivedBytes, 0, 16);
                                                        byte[] toDecryptPart = Arrays.copyOfRange(receivedBytes, 16, receivedBytes.length);

                                                        String strHisNonce = new String(Hex.encodeHex(hisNoncePart));
                                                        Constants.setHisNonce(strHisNonce);

                                                        Log.i("I:","P:1: Set Bob's nonce to:"+ strHisNonce);

                                                        byte[] salt = generateHashFromNonces(Constants.getMyNonce(), Constants.getHisNonce());

                                                        String strSalt = new String(Hex.encodeHex(salt));
                                                        Log.i("I:", "P:1: Salt generated from both nonces:"+ strSalt);

                                                        Utils u2 = new Utils();

                                                        byte[] keyForExchangeKeys = u2.deriveKey(Constants.getW(), salt, 1, 128);

                                                        String strDecKey = new String(Hex.encodeHex(keyForExchangeKeys));

                                                        Log.i("I:", "P:1: Key for exchange keys:"+ strDecKey);

                                                        Constants.setKeyForExchangeKeys(keyForExchangeKeys);
                                                        String decryptedMessage = decryptSymmetric(toDecryptPart, keyForExchangeKeys);

                                                        byte[] decryptedBytes = Hex.decodeHex(decryptedMessage.toCharArray());
                                                        byte[] myNoncePart = Arrays.copyOfRange(decryptedBytes, 0, 16);

                                                        String myNoncePartString = new String(Hex.encodeHex(myNoncePart));

                                                        if (myNoncePartString.compareTo(Constants.getMyNonce()) == 0) {

                                                            Log.i("I:", "P:1: first part of the nonce from Bob corresponds, go ahead and obtain his public key");

                                                            byte[] publicKeyPart = Arrays.copyOfRange(decryptedBytes, 16, decryptedBytes.length);

                                                            PublicKey hisPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyPart));
                                                            Constants.setHisPublicKey(hisPublicKey);

                                                            String pubKeyBobStr = new String(Hex.encodeHex(publicKeyPart));

                                                            Log.i("I:", "P:1: public key from Bob:"+ pubKeyBobStr);

                                                            Log.i("I:", "P:1: go ahead and generate my new public and private keys");
                                                            //generate my keys
                                                            //I get a pair of keys for RSA to set my public key/private key
                                                            Map<String, Object> keys = u2.getRSAKeys();

                                                            PrivateKey myPrivateKey = (PrivateKey) keys.get("private");
                                                            PublicKey myPublicKey = (PublicKey) keys.get("public");

                                                            Constants.setMyPrivateKey(myPrivateKey);

                                                            //Here the private key is going to be stored in the device
                                                            KeyFactory fact = KeyFactory.getInstance("RSA");
                                                            RSAPrivateKeySpec priv = fact.getKeySpec(myPrivateKey,
                                                                    RSAPrivateKeySpec.class);

                                                            File newfile = new File(Environment.getExternalStorageDirectory() + File.separator + PRIVATE_KEY_FILE);

                                                            u2.saveToFile(newfile,
                                                                    priv.getModulus(), priv.getPrivateExponent());

                                                            Constants.setMyPublicKey(myPublicKey);

                                                            //prepare the message to be sent in the 3rd step of the Public key exchange protocol

                                                            Log.i("I:", "P:1: now prepare the message to be sent on next step");
                                                            byte[] bytesMyPublicKey = Constants.getMyPublicKey().getEncoded();
                                                            String strMyPublicKey = new String(Hex.encodeHex(bytesMyPublicKey));

                                                            Log.i("I:", "P:1: my public key is:"+ strMyPublicKey);

                                                            byte[] bytesHisPublicKey = Constants.getHisPublicKey().getEncoded();
                                                            String strHisPublicKey = new String(Hex.encodeHex(bytesHisPublicKey));

                                                            Log.i("I:", "P:1: his public key is:"+ strHisPublicKey);

                                                            String messageToEncrypt = Constants.getHisNonce() + strMyPublicKey + strHisPublicKey;

                                                            Log.i("I:", "P:1: Message altogether before encryption is:"+ messageToEncrypt);

                                                            byte[] messageBytesToEncrypt = Hex.decodeHex(messageToEncrypt.toCharArray());

                                                            Log.i("I:", "P:1: first I ensure that I have saved on the db the key of Bob");
                                                            //alice saves the key for bob before sending the P:2 message
                                                            SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);

                                                            SQLiteDatabase db = mDbHelper.getReadableDatabase();

                                                            // Define a projection that specifies which columns from the database
                                                            // you will actually use after this query.

                                                            String[] projection = {
                                                                    SMSEncryptionContract.Directory._ID,
                                                                    SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                                    SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                                    SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                                    SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                                    SMSEncryptionContract.Directory.COLUMN_SESSION_KEY

                                                            };

                                                            // Filter results WHERE "title" = 'My Title'
                                                            String selection = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                            String[] selectionArgs = { originatingPhoneNumber };

                                                            Cursor cursor = db.query(
                                                                    SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                                    projection,                               // The columns to return
                                                                    selection,                                // The columns for the WHERE clause
                                                                    selectionArgs,                            // The values for the WHERE clause
                                                                    null,                                     // don't group the rows
                                                                    null,                                     // don't filter by row groups
                                                                    null                                      // The sort order
                                                            );

                                                            List itemIds = new ArrayList<>();
                                                            while(cursor.moveToNext()) {
                                                                long itemId = cursor.getLong(
                                                                        cursor.getColumnIndexOrThrow(SMSEncryptionContract.Directory._ID));
                                                                itemIds.add(itemId);
                                                            }
                                                            cursor.close();

                                                            SQLiteDatabase dbw = mDbHelper.getWritableDatabase();
                                                            ContentValues values = new ContentValues();

                                                            if (itemIds.size()==0){

                                                                Log.i("I:", "P:1: Bob's entry does not exist so insert a new row in the db for him and set his public key to:"+ strHisPublicKey);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_NAME, Constants.getHisContactName());
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER, originatingPhoneNumber);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY, strHisPublicKey);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY, Constants.getW());
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY, "none");

                                                                //Insert the row
                                                                long newRowId = dbw.insert(SMSEncryptionContract.Directory.TABLE_NAME, null, values);

                                                            }else{

                                                                Log.i("I:", "P:1: Bob's public key was already on the db so update it to:"+ strHisPublicKey);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY, strHisPublicKey);

                                                                // Which row to update, based on the title
                                                                String selectionUpdate = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                                String[] selectionArgsUpdate = { originatingPhoneNumber };

                                                                int count = db.update(
                                                                        SMSEncryptionContract.Directory.TABLE_NAME,
                                                                        values,
                                                                        selectionUpdate,
                                                                        selectionArgsUpdate);

                                                            }

                                                            if (db!=null){
                                                                db.close();
                                                            }

                                                            String finalMessage = encryptSymmetric(messageBytesToEncrypt, keyForExchangeKeys);
                                                            finalMessage = finalMessage + ":P:2";

                                                            Log.i("I:", "P:1: Final message after encryption:"+finalMessage);

                                                            //clear the variables to be reused on next transmission
                                                            Constants.setNumberMessages(0);
                                                            Constants.setDecryptionMessage("");

                                                            //send the message to receiver
                                                            SmsManager smsManager = SmsManager.getDefault();

                                                            PendingIntent sentIntent = PendingIntent.getBroadcast(context, 0,
                                                                    intent, 0);
                                                            context.getApplicationContext().registerReceiver(
                                                                    new SmsReceiver(),
                                                                    new IntentFilter(SENT_SMS_FLAG));

                                                            if (finalMessage.length() > 160) {

                                                                ArrayList<String> parts = u2.divideMessageManyParts(finalMessage);

                                                                for (int i = 0; i < parts.size() - 1; i++) {
                                                                    parts.set(i, parts.get(i) + ":P:2");
                                                                }

                                                                for (int j = 0; j < parts.size(); j++) {
                                                                    parts.set(j, parts.size() + "*" + parts.get(j));
                                                                }

                                                                for (int k = 0; k < parts.size(); k++) {
                                                                    smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                                            parts.get(k), sentIntent, null);
                                                                }
                                                            } else {
                                                                smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                                        finalMessage, sentIntent, null);
                                                            }

                                                        } else {
                                                            sessionErrorKey = true;
                                                            errorReason = "Message received in second step has no correspondence to the protocol";
                                                        }
                                                    } else {
                                                        sessionErrorKey = true;
                                                        errorReason = "Info to decrypt is null";
                                                    }

                                                }

                                            }

                                        } catch (Exception e) {
                                            e.printStackTrace();
                                            sessionErrorKey = true;
                                            errorReason = e.getMessage();
                                        }

                                        break;
                                    case 2:
                                        try {
                                            if (arr.length > 2) {

                                                String[] arrSplit2 = arr[0].split("\\*");

                                                Constants.setNumberMessages(Constants.getNumberMessages() + 1);
                                                Constants.setDecryptionMessage(Constants.getDecryptionMessage() + arrSplit2[1]);

                                                if (Integer.parseInt(arrSplit2[0]) == Constants.getNumberMessages()) {

                                                    infoToDecrypt = Constants.getDecryptionMessage();

                                                    if (!infoToDecrypt.isEmpty()) {

                                                        Log.i("I:", "P:2: Received message before decryption:"+ infoToDecrypt);

                                                        byte[] receivedBytes = Hex.decodeHex(infoToDecrypt.toCharArray());

                                                        String decryptedMessage = decryptSymmetric(receivedBytes, Constants.getKeyForExchangeKeys());

                                                        Log.i("I:", "P:2: After decryption:"+ decryptedMessage);

                                                        byte[] decryptedBytes = Hex.decodeHex(decryptedMessage.toCharArray());

                                                        byte[] noncePart = Arrays.copyOfRange(decryptedBytes, 0, 16);

                                                        String noncePartReceived = new String(Hex.encodeHex(noncePart));

                                                        Log.i("I:","P:2: First 16 bytes correspond to the nonce of Bob and is:"+ noncePartReceived);

                                                        if (noncePartReceived.compareTo(Constants.getMyNonce()) == 0) {

                                                            Log.i("I:", "P:2: Since both nonces correspond then set now the public key from Alice");
                                                            byte[] publicKeyA = Arrays.copyOfRange(decryptedBytes, 16, 310);
                                                            byte[] publicKeyB = Arrays.copyOfRange(decryptedBytes, 310, 604);

                                                            String strPubKeyA = new String(Hex.encodeHex(publicKeyA));
                                                            String strPubKeyB = new String(Hex.encodeHex(publicKeyB));

                                                            Log.i("I:", "P:2: Alice's public key is:"+ strPubKeyA);

                                                            SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);

                                                            SQLiteDatabase db = mDbHelper.getReadableDatabase();

                                                            // Define a projection that specifies which columns from the database
                                                            // you will actually use after this query.

                                                            String[] projection = {
                                                                    SMSEncryptionContract.Directory._ID,
                                                                    SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                                    SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                                    SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                                    SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                                    SMSEncryptionContract.Directory.COLUMN_SESSION_KEY
                                                            };

                                                            String selection = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                            String[] selectionArgs = { originatingPhoneNumber };

                                                            Cursor cursor = db.query(
                                                                    SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                                    projection,                               // The columns to return
                                                                    selection,                                // The columns for the WHERE clause
                                                                    selectionArgs,                            // The values for the WHERE clause
                                                                    null,                                     // don't group the rows
                                                                    null,                                     // don't filter by row groups
                                                                    null                                      // The sort order
                                                            );

                                                            List itemIds = new ArrayList<>();
                                                            while(cursor.moveToNext()) {
                                                                long itemId = cursor.getLong(
                                                                        cursor.getColumnIndexOrThrow(SMSEncryptionContract.Directory._ID));
                                                                itemIds.add(itemId);
                                                            }
                                                            cursor.close();

                                                            SQLiteDatabase dbw = mDbHelper.getWritableDatabase();

                                                            //save values on the database
                                                            ContentValues values = new ContentValues();

                                                            if (itemIds.size()==0){

                                                                Log.i("I:", "P:2: Alice's public key is not set so insert it now in the database: "+ strPubKeyA);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_NAME, Constants.getHisContactName());
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER, originatingPhoneNumber);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY, strPubKeyA);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY, Constants.getW());
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY, "none");

                                                                //Insert the row
                                                                long newRowId = dbw.insert(SMSEncryptionContract.Directory.TABLE_NAME, null, values);
                                                            }else{

                                                                Log.i("I:", "P:2: Alice's public key is present in the database so UPDATE IT to: "+strPubKeyA);
                                                                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY, strPubKeyA);

                                                                // Which row to update, based on the title
                                                                String selectionUpdate = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                                String[] selectionArgsUpdate = { originatingPhoneNumber };

                                                                int count = db.update(
                                                                        SMSEncryptionContract.Directory.TABLE_NAME,
                                                                        values,
                                                                        selectionUpdate,
                                                                        selectionArgsUpdate);

                                                            }

                                                            String myPubKey = new String(Hex.encodeHex(Constants.getMyPublicKey().getEncoded()));

                                                            Log.i("I:", "P:2: Now compare if the obtained public key B in the message corresponds to my public key.");

                                                            TelephonyManager tMgr = (TelephonyManager)context.getSystemService(context.TELEPHONY_SERVICE);
                                                            String myPhoneNumber = tMgr.getLine1Number();

                                                            String selectionMyself = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                            String[] selectionArgsMyself = { myPhoneNumber };

                                                            Cursor cursorMyself = db.query(
                                                                    SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                                    projection,                               // The columns to return
                                                                    selectionMyself,                                // The columns for the WHERE clause
                                                                    selectionArgsMyself,                            // The values for the WHERE clause
                                                                    null,                                     // don't group the rows
                                                                    null,                                     // don't filter by row groups
                                                                    null                                      // The sort order
                                                            );

                                                            List itemPubKeys = new ArrayList<>();
                                                            while(cursorMyself.moveToNext()) {
                                                                String itemPubKey = cursorMyself.getString(
                                                                        cursorMyself.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY));
                                                                itemPubKeys.add(itemPubKey);
                                                            }
                                                            cursorMyself.close();


                                                            if (db!=null){
                                                                db.close();
                                                            }

                                                            if(dbw!=null){
                                                                dbw.close();
                                                            }

                                                            if (strPubKeyB.compareTo(itemPubKeys.get(0).toString())==0) {

                                                                Log.i("I:", "P:2: Yes the public keys from Bob correspond, in Bob's database vs. public key in the message");
                                                                PublicKey hisPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyA));

                                                                Constants.setHisPublicKey(hisPublicKey);

                                                                Log.i("I:", "P:2: About to encrypt the public key from alice with the exchange key");

                                                                String messageToBeSent = encryptSymmetric(Constants.getHisPublicKey().getEncoded(), Constants.getKeyForExchangeKeys());

                                                                messageToBeSent = messageToBeSent + ":P:3";

                                                                Log.i("I:", "P:2: Message to be sent (already encrypted) is:"+ messageToBeSent);

                                                                //clear the variables to be reused on next transmission
                                                                Constants.setNumberMessages(0);
                                                                Constants.setDecryptionMessage("");

                                                                Utils u3 = new Utils();
                                                                //send the message to receiver
                                                                SmsManager smsManager = SmsManager.getDefault();

                                                                PendingIntent sentIntent = PendingIntent.getBroadcast(context, 0,
                                                                        intent, 0);
                                                                context.getApplicationContext().registerReceiver(
                                                                        new SmsReceiver(),
                                                                        new IntentFilter(SENT_SMS_FLAG));

                                                                if (messageToBeSent.length() > 160) {

                                                                    ArrayList<String> parts = u3.divideMessageManyParts(messageToBeSent);

                                                                    for (int i = 0; i < parts.size() - 1; i++) {
                                                                        parts.set(i, parts.get(i) + ":P:3");
                                                                    }

                                                                    for (int j = 0; j < parts.size(); j++) {
                                                                        parts.set(j, parts.size() + "*" + parts.get(j));
                                                                    }

                                                                    for (int k = 0; k < parts.size(); k++) {
                                                                        smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                                                parts.get(k), sentIntent, null);
                                                                    }
                                                                } else {
                                                                    smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                                            messageToBeSent, sentIntent, null);
                                                                }



                                                            } else {
                                                                errorReason = "Step 2: Public key sent does not correspond to the one in the receiver.";
                                                                sessionErrorKey = true;
                                                            }

                                                        } else {
                                                            errorReason = "Step 2: The nonce sent does not correspond to the one in the receiver.";
                                                            sessionErrorKey = true;
                                                        }
                                                    }

                                                }
                                            }
                                        } catch (NoSuchAlgorithmException e) {
                                            e.printStackTrace();
                                        } catch (DecoderException e) {
                                            e.printStackTrace();
                                        } catch (InvalidKeySpecException e) {
                                            e.printStackTrace();
                                        }

                                        break;

                                    case 3:
                                        try {
                                            if (arr.length > 2) {

                                                String[] arrSplit3 = arr[0].split("\\*");

                                                Constants.setNumberMessages(Constants.getNumberMessages() + 1);
                                                Constants.setDecryptionMessage(Constants.getDecryptionMessage() + arrSplit3[1]);

                                                if (Integer.parseInt(arrSplit3[0]) == Constants.getNumberMessages()) {

                                                    infoToDecrypt = Constants.getDecryptionMessage();

                                                    if (!infoToDecrypt.isEmpty()) {

                                                        Log.i("I:","P:3: Info received before decrypting it:"+ infoToDecrypt);

                                                        byte[] receivedBytes = Hex.decodeHex(infoToDecrypt.toCharArray());

                                                        String decryptedMessage = decryptSymmetric(receivedBytes, Constants.getKeyForExchangeKeys());

                                                        Log.i("I:", "P:3: Message decrypted is:"+ decryptedMessage);

                                                        byte[] decryptedBytes = Hex.decodeHex(decryptedMessage.toCharArray());
                                                        String pubKeyStr = new String(Hex.encodeHex(decryptedBytes));

                                                        PublicKey pk = Constants.getMyPublicKey();
                                                        byte[] pkencoded = pk.getEncoded();
                                                        String pubKeyEncoded = new String(Hex.encodeHex(pkencoded));

                                                        //I need to compare if it corresponds to my own public key
                                                        if (pubKeyStr.compareTo(pubKeyEncoded)==0) {

                                                            Log.i("I:", "P:3: It corresponds to my public key (Alice)");
                                                            //clear the variables to be reused on next transmission
                                                            Constants.setNumberMessages(0);
                                                            Constants.setDecryptionMessage("");

                                                            SmsManager smsManager = SmsManager.getDefault();

                                                            PendingIntent sentIntent = PendingIntent.getBroadcast(context, 0,
                                                                    intent, 0);
                                                            context.getApplicationContext().registerReceiver(
                                                                    new SmsReceiver(),
                                                                    new IntentFilter(SENT_SMS_FLAG));
                                                            smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                                    "Success! Protocol has been established:E", sentIntent, null);

                                                            Toast.makeText(context, "Success!, the protocol has been established", Toast.LENGTH_SHORT).show();

                                                            Intent i = new Intent(context, PhoneBookActivity.class);
                                                            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                                                            context.startActivity(i);


                                                        } else {
                                                            errorReason = "Step 3: Public key sent does not correspond to the receivers public key";
                                                            sessionErrorKey = true;
                                                        }

                                                    }

                                                }
                                            }

                                        } catch (Exception e) {
                                            e.printStackTrace();
                                        }
                                        break;
                                }

                            }

                            if (protocolId.compareTo("E") == 0) {
                                    //run protocol from the message exchange encryption

                                //return to the phonebook list and show the new added contact

                                Constants.setNumberMessages(0);
                                Constants.setDecryptionMessage("");

                                Intent i = new Intent(context, PhoneBookActivity.class);
                                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                                context.startActivity(i);

                                    } else {
                                    if (protocolId.compareTo("W") == 0) {
                                        //received the initial W
                                        Constants.setW(receivedMessage);
                                    }else{
                                        if (protocolId.compareTo("S")==0){
                                            //to establish the session key here
                                            //send sms step S:1
                                            switch (stepProtocol) {
                                                case 0:

                                                    Log.i("I:", "S:0: my long term key W is:"+ Constants.getW());
                                                    Log.i("I:", "S:0: set his nonce to:"+ receivedMessage);

                                                    Constants.setHisNonce(receivedMessage);

                                                    //clear these variables just in case
                                                    Constants.setNumberMessages(0);
                                                    Constants.setDecryptionMessage("");

                                                    //generate my nonce
                                                    Utils u = new Utils();
                                                    String nonceGenerated = u.generateNonce();
                                                    Constants.setMyNonce(nonceGenerated);

                                                    Log.i("I:","S:0: Nonce generated:"+ Constants.getMyNonce());

                                                    String messageToSend = Constants.getMyNonce() + Constants.getHisNonce();

                                                    messageToSend = messageToSend + ":S:1";

                                                    Log.i("I:", "S:0: message to send in S:1:"+messageToSend);

                                                    //check if the W was set or not

                                                    SMSEncryptionDbHelper mDbHelperLTK = new SMSEncryptionDbHelper(context);

                                                    SQLiteDatabase dbLTK = mDbHelperLTK.getReadableDatabase();

                                                    String[] projectionLTK = {
                                                            SMSEncryptionContract.Directory._ID,
                                                            SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                            SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                            SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                            SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                            SMSEncryptionContract.Directory.COLUMN_SESSION_KEY

                                                    };

                                                    // Filter results WHERE "title" = 'My Title'
                                                    String selectionLTK = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                    String[] selectionArgsLTK = { originatingPhoneNumber };

                                                    Cursor cursorLTK = dbLTK.query(
                                                            SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                            projectionLTK,                               // The columns to return
                                                            selectionLTK,                                // The columns for the WHERE clause
                                                            selectionArgsLTK,                            // The values for the WHERE clause
                                                            null,                                     // don't group the rows
                                                            null,                                     // don't filter by row groups
                                                            null                                      // The sort order
                                                    );

                                                    List itemLongTermKeys1 = new ArrayList();
                                                    List itemHisPK = new ArrayList<>();

                                                    while(cursorLTK.moveToNext()) {
                                                        String longTermKeyStr = cursorLTK.getString(cursorLTK.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY));
                                                        itemLongTermKeys1.add(longTermKeyStr);

                                                        Log.i("I:", "S:0: Long term key from db of ALice:"+ longTermKeyStr);

                                                        String hisPK = cursorLTK.getString(cursorLTK.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY));
                                                        itemHisPK.add(hisPK);

                                                        Log.i("I:", "S:0: Public key from Alice:"+ hisPK);
                                                    }
                                                    cursorLTK.close();

                                                    if ((itemLongTermKeys1.size()>0)&&(itemHisPK.size()>0)){
                                                        Constants.setW(itemLongTermKeys1.get(0).toString());

                                                        Log.i("I:", "S:0: setting long term key to:"+ itemLongTermKeys1.get(0).toString());

                                                        try{
                                                            byte[] bytesPublicKey = Hex.decodeHex(itemHisPK.get(0).toString().toCharArray());
                                                            PublicKey hisPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytesPublicKey));
                                                            Constants.setHisPublicKey(hisPublicKey);
                                                        }//string to public key
                                                        catch(Exception e){
                                                            e.printStackTrace();
                                                        }
                                                    }

                                                    if (dbLTK!=null){
                                                        dbLTK.close();
                                                    }

                                                    SmsManager smsManager = SmsManager.getDefault();

                                                    PendingIntent sentIntent = PendingIntent.getBroadcast(context, 0,
                                                            intent, 0);
                                                    context.getApplicationContext().registerReceiver(
                                                            new SmsReceiver(),
                                                            new IntentFilter(SENT_SMS_FLAG));
                                                    smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                            messageToSend , sentIntent, null);

                                                    Toast.makeText(context, messageToSend, Toast.LENGTH_SHORT).show();

                                                    break;
                                                case 1:

                                                    Log.i("I:", "S:1: Get the w:"+ Constants.getW());
                                                    //clear these variables just in case
                                                    Constants.setNumberMessages(0);
                                                    Constants.setDecryptionMessage("");

                                                    //from this message since the nonces are new, alice should check his nonce appended
                                                    try{
                                                        byte[] receivedByteArray = Hex.decodeHex(receivedMessage.toCharArray());
                                                        byte[] bytesNa = new byte[16];
                                                        byte[] bytesNb = new byte[16];

                                                        System.arraycopy(receivedByteArray, 0, bytesNb, 0, bytesNb.length);
                                                        System.arraycopy(receivedByteArray, 16, bytesNa, 0, bytesNa.length);

                                                        String naReceivedStr = new String(Hex.encodeHex(bytesNa));
                                                        String nbReceivedStr = new String(Hex.encodeHex(bytesNb));

                                                        Log.i("I:", "S:1: nonce A received:"+ naReceivedStr);
                                                        Log.i("I:", "S:1: nonce B received:"+ nbReceivedStr);

                                                        if (Constants.getMyNonce().compareTo(naReceivedStr)==0){
                                                            //meaning that it is okay and we can proceed with next step
                                                            Constants.setHisNonce(nbReceivedStr);
                                                            //generate a hash as salt and a material also passed to generate a key
                                                            Utils u2 = new Utils();

                                                            byte[] salt = new byte[0];
                                                            try {
                                                                String strMaterial = Constants.getHisNonce()+Constants.getMyNonce();

                                                                Log.i("I:","S:1: strMaterial is:"+ strMaterial);

                                                                Log.i("I:", "S:1: his nonce is:"+ Constants.getHisNonce());

                                                                Log.i("I:", "S:1: my nonce is:"+ Constants.getMyNonce());

                                                                salt = generateHashFromNonces(Constants.getHisNonce(), Constants.getMyNonce());

                                                                byte[] sessionKey = u2.deriveKey(strMaterial, salt, 1, 128);

                                                                String sessionKeyStr = new String(Hex.encodeHex(sessionKey));
                                                                Constants.setSessionKey(sessionKeyStr);

                                                                Log.i("I:", "S:1: session key generated:"+sessionKeyStr);

                                                                //get his public key from the database
                                                                SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);

                                                                SQLiteDatabase db = mDbHelper.getReadableDatabase();

                                                                String[] projection = {
                                                                        SMSEncryptionContract.Directory._ID,
                                                                        SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                                        SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                                        SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                                        SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                                        SMSEncryptionContract.Directory.COLUMN_SESSION_KEY

                                                                };

                                                                // Filter results WHERE "title" = 'My Title'
                                                                String selection = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                                String[] selectionArgs = { originatingPhoneNumber };

                                                                Cursor cursorPK = db.query(
                                                                        SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                                        projection,                               // The columns to return
                                                                        selection,                                // The columns for the WHERE clause
                                                                        selectionArgs,                            // The values for the WHERE clause
                                                                        null,                                     // don't group the rows
                                                                        null,                                     // don't filter by row groups
                                                                        null                                      // The sort order
                                                                );

                                                                List itemPublicKeys = new ArrayList<>();
                                                                List itemLongTermKeys = new ArrayList();

                                                                while(cursorPK.moveToNext()) {
                                                                    String pubKey = cursorPK.getString(cursorPK.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY));
                                                                        itemPublicKeys.add(pubKey);

                                                                    String longTermKeyStr = cursorPK.getString(cursorPK.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY));
                                                                    itemLongTermKeys.add(longTermKeyStr);
                                                                }
                                                                cursorPK.close();

                                                                //public key is obtained from the database
                                                                String hisPublicKeyStr = itemPublicKeys.get(0).toString();

                                                                Log.i("I:","S:1: his public key from db is:"+ hisPublicKeyStr);

                                                                String hisLongTermKeyFromDB = itemLongTermKeys.get(0).toString();

                                                                Log.i("I:","S:1: his long term key from db is:"+ hisLongTermKeyFromDB);

                                                                if (db!=null){
                                                                    db.close();
                                                                }

                                                                try {
                                                                    byte[] bytesPublicKey = Hex.decodeHex(hisPublicKeyStr.toCharArray());
                                                                    PublicKey hisPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytesPublicKey));

                                                                    String encryptedFirstPart = encryptAsymmetric(sessionKey, hisPublicKey);
                                                                    Log.i("I:","S:1: encrypted first part is:"+encryptedFirstPart);

                                                                    String secondPartToEncrypt = Constants.getHisNonce() + hisLongTermKeyFromDB;

                                                                    byte[] secondPartToEncryptInBytes = Hex.decodeHex(secondPartToEncrypt.toCharArray());

                                                                    String encryptedSecondPart = encryptSymmetric(secondPartToEncryptInBytes, sessionKey);

                                                                    Log.i("I:", "S:1: encrypted second part is:"+encryptedSecondPart);

                                                                    String finalMessage = encryptedFirstPart + encryptedSecondPart;

                                                                    finalMessage = finalMessage + ":S:2";

                                                                    Log.i("I:", "S:1: final message is:"+ finalMessage);

                                                                    Utils u4 = new Utils();
                                                                    //send the message to receiver
                                                                    SmsManager smsManager2 = SmsManager.getDefault();

                                                                    PendingIntent sentIntent2 = PendingIntent.getBroadcast(context, 0,
                                                                            intent, 0);
                                                                    context.getApplicationContext().registerReceiver(
                                                                            new SmsReceiver(),
                                                                            new IntentFilter(SENT_SMS_FLAG));

                                                                    if (finalMessage.length() > 160) {

                                                                        ArrayList<String> parts2 = u4.divideMessageManyParts(finalMessage);

                                                                        for (int i = 0; i < parts2.size() - 1; i++) {
                                                                            parts2.set(i, parts2.get(i) + ":S:2");
                                                                        }

                                                                        for (int j = 0; j < parts2.size(); j++) {
                                                                            parts2.set(j, parts2.size() + "*" + parts2.get(j));
                                                                        }

                                                                        for (int k = 0; k < parts2.size(); k++) {
                                                                            Log.i("to send in step 2:", parts2.get(k));
                                                                            smsManager2.sendTextMessage(originatingPhoneNumber, null,
                                                                                    parts2.get(k), sentIntent2, null);
                                                                        }
                                                                    } else {
                                                                        smsManager2.sendTextMessage(originatingPhoneNumber, null,
                                                                                finalMessage, sentIntent2, null);
                                                                    }

                                                                } catch (Exception e) {
                                                                    e.printStackTrace();
                                                                    Log.i("i:","cannot load the public key from the database");
                                                                }

                                                            } catch (UnsupportedEncodingException e) {
                                                                e.printStackTrace();
                                                            } catch (NoSuchAlgorithmException e) {
                                                                e.printStackTrace();
                                                            } catch (java.lang.Exception e){
                                                                e.printStackTrace();
                                                            }

                                                        }
                                                        else{
                                                            //TODO: set an error message
                                                            errorReason = "SK Establishment: nonce received does not correspond to my nonce";
                                                            sessionErrorKey = true;
                                                        }

                                                    }catch(DecoderException e){
                                                        e.printStackTrace();
                                                    }


                                                break;
                                                case 2:
                                                    try{
                                                        if (arr.length > 2) {

                                                            String[] arrSplit4 = arr[0].split("\\*");

                                                            Constants.setNumberMessages(Constants.getNumberMessages() + 1);
                                                            Constants.setDecryptionMessage(Constants.getDecryptionMessage() + arrSplit4[1]);

                                                            if (Integer.parseInt(arrSplit4[0]) == Constants.getNumberMessages()) {

                                                                infoToDecrypt = Constants.getDecryptionMessage();

                                                                if (!infoToDecrypt.isEmpty()) {
                                                                    try {
                                                                        byte[] receivedBytes = Hex.decodeHex(infoToDecrypt.toCharArray());

                                                                        //from here need to decrypt the first part asymmetrically and the second part symmetrically
                                                                        String strReceived = new String(Hex.encodeHex(receivedBytes));

                                                                        Log.i("I:", "S:2: str received:"+ strReceived);

                                                                        byte[] firstPartToDecrypt = new byte[256];

                                                                        System.arraycopy(receivedBytes, 0, firstPartToDecrypt, 0, firstPartToDecrypt.length);

                                                                        int secondPartSize =receivedBytes.length - 256;

                                                                        byte[] secondPartToDecrypt = new byte[secondPartSize];

                                                                        System.arraycopy(receivedBytes, 256, secondPartToDecrypt, 0, secondPartSize);

                                                                            Utils u3 = new Utils();

                                                                            try {
                                                                                File fileToRead = new File(Environment.getExternalStorageDirectory() + File.separator + PRIVATE_KEY_FILE);
                                                                                PrivateKey privKeyFromDevice = u3.readPrivateKey(fileToRead);

                                                                                if (privKeyFromDevice!=null){
                                                                                    //set in my current execution
                                                                                    Log.i("I:","S:2: setting my private key from device");
                                                                                    Constants.setMyPrivateKey(privKeyFromDevice);
                                                                                }

                                                                            }catch(Exception e){
                                                                                Log.i("I:", "S:2: cannot read my private key");
                                                                                e.printStackTrace();
                                                                            }

                                                                        PrivateKey myPk = Constants.getMyPrivateKey();

                                                                        String strfirstpartdecrypt = new String(Hex.encodeHex(firstPartToDecrypt));

                                                                        Log.i("I:","S:2: first part to decrypt:"+ strfirstpartdecrypt);

                                                                        byte[] bytesMyPrivateKey = myPk.getEncoded();
                                                                        String strMyPrivateKey = new String(Hex.encodeHex(bytesMyPrivateKey));

                                                                        Log.i("I:", "S:2: strMyPrivateKey:"+ strMyPrivateKey);

                                                                        String firstDecryptionAsymmetric = decryptAsymmetric(firstPartToDecrypt, myPk);

                                                                        Log.i("I:", "S:2: first part after decryption:"+ firstDecryptionAsymmetric);

                                                                        String sessionKey = firstDecryptionAsymmetric;
                                                                        Constants.setSessionKey(sessionKey);

                                                                        Log.i("I:", "S:2: session key:"+ Constants.getSessionKey());

                                                                        byte[] sessionKeyBytes = Hex.decodeHex(sessionKey.toCharArray());

                                                                        SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);

                                                                        SQLiteDatabase dbb = mDbHelper.getReadableDatabase();

                                                                        String[] projectionb = {
                                                                                SMSEncryptionContract.Directory._ID,
                                                                                SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                                                SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                                                SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                                                SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                                                SMSEncryptionContract.Directory.COLUMN_SESSION_KEY
                                                                        };

                                                                        // Filter results WHERE "title" = 'My Title'
                                                                        String selectionb = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                                        String[] selectionArgsb = { originatingPhoneNumber };

                                                                        Cursor cursorb = dbb.query(
                                                                                SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                                                projectionb,                               // The columns to return
                                                                                selectionb,                                // The columns for the WHERE clause
                                                                                selectionArgsb,                            // The values for the WHERE clause
                                                                                null,                                     // don't group the rows
                                                                                null,                                     // don't filter by row groups
                                                                                null                                      // The sort order
                                                                        );

                                                                        List itemLTK = new ArrayList<>();
                                                                        while(cursorb.moveToNext()) {
                                                                            String ltk = cursorb.getString(cursorb.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY));
                                                                            itemLTK.add(ltk);
                                                                        }
                                                                        cursorb.close();

                                                                        if (itemLTK.size()>0){
                                                                            //meaning that it is not set
                                                                            Constants.setW(itemLTK.get(0).toString());
                                                                            Log.i("I:", "S:2: W set from db: "+ Constants.getW());

                                                                        }

                                                                        //second part is accesible via symmetric encryption with the session key obtained in the step before

                                                                        String secondDecryptionSymmetric = decryptSymmetric(secondPartToDecrypt, sessionKeyBytes);

                                                                        Log.i("I:", "S:2: second decryption symmetric string: "+ secondDecryptionSymmetric);

                                                                        byte[] secondDecryptionBytes = Hex.decodeHex(secondDecryptionSymmetric.toCharArray());

                                                                        byte[] nonceToCheck = new byte[16];
                                                                        System.arraycopy(secondDecryptionBytes, 0, nonceToCheck, 0, nonceToCheck.length);

                                                                        int remainSize = secondDecryptionBytes.length - 16;
                                                                        byte[] longTermPartBytes = new byte[remainSize];
                                                                        System.arraycopy(secondDecryptionBytes, 16, longTermPartBytes, 0 , remainSize);

                                                                        String strNonceToCheck = new String(Hex.encodeHex(nonceToCheck));

                                                                        Log.i("I:", "S:2: nonce to check:"+ strNonceToCheck);

                                                                        String strWToCheck = new String(Hex.encodeHex(longTermPartBytes));

                                                                        Log.i("I:", "S:2: W to check:"+ strWToCheck);

                                                                        if (Constants.getMyNonce().compareTo(strNonceToCheck)==0){

                                                                            Log.i("I:", "S:2: nonce to check corresponds, next validation is W");

                                                                            if (Constants.getW().compareTo(strWToCheck)==0){
                                                                                //send alice's nonce to alice encrypted with the session key

                                                                                Log.i("I:", "S:2: W corresponds, now update the new session key in db");

                                                                                byte[] messageBytes = Hex.decodeHex(Constants.getHisNonce().toCharArray());

                                                                                String nonceEncrypted = encryptSymmetric(messageBytes, sessionKeyBytes);

                                                                                //TODO: update the field "sessionkey" in database

                                                                                ContentValues values = new ContentValues();

                                                                                values.put(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY, Constants.getSessionKey());

                                                                                // Which row to update, based on the title
                                                                                String selectionUpdate = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " LIKE ?";
                                                                                String[] selectionArgsUpdate = { originatingPhoneNumber };

                                                                                int count = dbb.update(
                                                                                        SMSEncryptionContract.Directory.TABLE_NAME,
                                                                                        values,
                                                                                        selectionUpdate,
                                                                                        selectionArgsUpdate);

                                                                                if (dbb!=null){
                                                                                    dbb.close();
                                                                                }

                                                                                String lastMessage = nonceEncrypted + ":S:3";

                                                                                //clear the variables to be reused on next transmission
                                                                                Constants.setNumberMessages(0);
                                                                                Constants.setDecryptionMessage("");

                                                                                SmsManager smsManager3 = SmsManager.getDefault();

                                                                                PendingIntent sentIntent3 = PendingIntent.getBroadcast(context, 0,
                                                                                        intent, 0);
                                                                                context.getApplicationContext().registerReceiver(
                                                                                        new SmsReceiver(),
                                                                                        new IntentFilter(SENT_SMS_FLAG));
                                                                                smsManager3.sendTextMessage(originatingPhoneNumber, null,
                                                                                        lastMessage , sentIntent3, null);

                                                                                Toast.makeText(context, lastMessage, Toast.LENGTH_SHORT).show();

                                                                            }
                                                                            else{
                                                                                errorReason = "S:2: SK Establishment: Long term key does not correspond";
                                                                                sessionErrorKey = true;
                                                                            }

                                                                        }
                                                                        else{
                                                                            errorReason = "S:2: SK Establishment: nonce received does not correspond";
                                                                            sessionErrorKey = true;
                                                                        }
                                                                    } catch (DecoderException e) {
                                                                        e.printStackTrace();
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }catch(Exception e){
                                                        e.printStackTrace();
                                                    }
                                                break;
                                                case 3:

                                                    try{
                                                        byte[] messageInBytes = Hex.decodeHex(receivedMessage.toCharArray());
                                                        byte[] sessionKeyBytes = Hex.decodeHex(Constants.getSessionKey().toCharArray());

                                                        String decryptedMessage = decryptSymmetric(messageInBytes, sessionKeyBytes);

                                                        //need to check that this decrypted message corresponds to my nonce
                                                        if (Constants.getMyNonce().compareTo(decryptedMessage)==0){

                                                            SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);

                                                            SQLiteDatabase db = mDbHelper.getReadableDatabase();
                                                            //update the session key in the database
                                                            ContentValues values = new ContentValues();

                                                            Log.i("I:","S:3: need to update the session key to:"+ Constants.getSessionKey());

                                                            values.put(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY, Constants.getSessionKey());

                                                            // Which row to update, based on the title
                                                            String selectionUpdate = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                            String[] selectionArgsUpdate = { originatingPhoneNumber };

                                                            int count = db.update(
                                                                    SMSEncryptionContract.Directory.TABLE_NAME,
                                                                    values,
                                                                    selectionUpdate,
                                                                    selectionArgsUpdate);

                                                            Log.i("I:","S:3: updating # rows:"+ count);

                                                            if (db!=null){
                                                                db.close();
                                                            }

                                                            //clear the variables to be reused on next transmission
                                                            Constants.setNumberMessages(0);
                                                            Constants.setDecryptionMessage("");

                                                            //if this is okay then send a message to Bob saying the session key was correctly established
                                                            String confirmationMessage =  "Success: session key has been set in the receiver!";

                                                            SmsManager smsManager4 = SmsManager.getDefault();

                                                            PendingIntent sentIntent4 = PendingIntent.getBroadcast(context, 0,
                                                                    intent, 0);
                                                            context.getApplicationContext().registerReceiver(
                                                                    new SmsReceiver(),
                                                                    new IntentFilter(SENT_SMS_FLAG));
                                                            smsManager4.sendTextMessage(originatingPhoneNumber, null,
                                                                    confirmationMessage , sentIntent4, null);

                                                            Toast.makeText(context, confirmationMessage, Toast.LENGTH_SHORT).show();

                                                        }else{
                                                            errorReason= "S:3: SK Establishment: error: nonces does not correspond";
                                                            sessionErrorKey = true;
                                                        }
                                                    }
                                                    catch (DecoderException e) {
                                                        e.printStackTrace();
                                                        errorReason= "S:3: SK Establishment: error in decryption last message";
                                                        sessionErrorKey = true;
                                                    }

                                                    break;
                                            }

                                        }
                                        else{
                                            if (protocolId.compareTo("M")==0){
                                                //decrypt the message received and save it on the db

                                                Log.i("I:", "M: Sending a message with session key established");
                                                SMSEncryptionDbHelper mDbHelperSK = new SMSEncryptionDbHelper(context);

                                                SQLiteDatabase dbSK = mDbHelperSK.getReadableDatabase();

                                                String[] projection = {
                                                        SMSEncryptionContract.Directory._ID,
                                                        SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                        SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                        SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                        SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                        SMSEncryptionContract.Directory.COLUMN_SESSION_KEY
                                                };

                                                // Filter results WHERE "title" = 'My Title'
                                                String selection = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                String[] selectionArgs = { originatingPhoneNumber };

                                                Cursor cursor = dbSK.query(
                                                        SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                        projection,                               // The columns to return
                                                        selection,                                // The columns for the WHERE clause
                                                        selectionArgs,                            // The values for the WHERE clause
                                                        null,                                     // don't group the rows
                                                        null,                                     // don't filter by row groups
                                                        null                                      // The sort order
                                                );

                                                List itemSessionKey = new ArrayList<>();
                                                while(cursor.moveToNext()) {
                                                    String sessionKey = cursor.getString(cursor.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY));
                                                    itemSessionKey.add(sessionKey);
                                                    Log.i("I:", "M: Session key from db: "+sessionKey);
                                                }
                                                cursor.close();

                                                if (dbSK!=null){
                                                    dbSK.close();
                                                }

                                                if (itemSessionKey.get(0).toString().compareTo("none")==0){
                                                    Toast.makeText(context, "M: Error: The session key has not been established.", Toast.LENGTH_SHORT).show();
                                                }else{
                                                    try {

                                                        //session key obtained from the db
                                                        String sessionKeyStr = itemSessionKey.get(0).toString();

                                                        byte[] sessionKeyBytes = Hex.decodeHex(sessionKeyStr.toCharArray());
                                                        byte[] receivedBytes = receivedMessage.getBytes("UTF-8");

                                                        String decryptedMessage = decryptSymmetrically(receivedBytes, sessionKeyBytes);

                                                        Toast.makeText(context, "M: Message: "+decryptedMessage, Toast.LENGTH_SHORT).show();
                                                        // this message should be inserted into the database

                                                        Utils utilities = new Utils();

                                                        SQLiteDatabase dbw = mDbHelperSK.getWritableDatabase();
                                                        ContentValues values = new ContentValues();
                                                        //save values on the database

                                                        values.put(SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER, originatingPhoneNumber);
                                                        values.put(SMSEncryptionContract.Messages.COLUMN_RECEIVER_PHONENUMBER, Constants.getReceiverPhoneNumber());
                                                        values.put(SMSEncryptionContract.Messages.COLUMN_CONTENT, decryptedMessage);
                                                        values.put(SMSEncryptionContract.Messages.COLUMN_TIME, utilities.getDateTime());

                                                        //Insert the row
                                                        long newRowId = dbw.insert(SMSEncryptionContract.Messages.TABLE_NAME, null, values);

                                                        SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);
                                                        SQLiteDatabase db = mDbHelper.getReadableDatabase();

                                                        String[] projectionDb = {
                                                                SMSEncryptionContract.Directory._ID,
                                                                SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                                                SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                                                SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                                                SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                                                SMSEncryptionContract.Directory.COLUMN_SESSION_KEY
                                                        };

                                                        // Filter results WHERE "title" = 'My Title'
                                                        String selectionDb = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                                                        String[] selectionArgsDb = { originatingPhoneNumber };

                                                        Cursor cursorDb = db.query(
                                                                SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                                                projectionDb,                               // The columns to return
                                                                selectionDb,                                // The columns for the WHERE clause
                                                                selectionArgsDb,                            // The values for the WHERE clause
                                                                null,                                     // don't group the rows
                                                                null,                                     // don't filter by row groups
                                                                null                                      // The sort order
                                                        );

                                                        List itemSK = new ArrayList<>();

                                                        while(cursorDb.moveToNext()) {
                                                            String sk = cursorDb.getString(cursorDb.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY));
                                                            itemSK.add(sk);

                                                        }
                                                        cursor.close();

                                                        Intent i = new Intent(context, SendMessageActivity.class);

                                                        TelephonyManager tMgr = (TelephonyManager)context.getSystemService(context.TELEPHONY_SERVICE);
                                                        String myPhoneNumber = tMgr.getLine1Number();

                                                        i.putExtra("SESSION_KEY", itemSK.get(0).toString());

                                                        Log.i("I:", "Extras: RECEIVER_PHONENUMBER:"+ originatingPhoneNumber);
                                                        Log.i("I:", "Extras: MYPHONENUMBER:"+ myPhoneNumber);

                                                        if (db!=null){
                                                            db.close();
                                                        }

                                                        if (dbw!=null){
                                                            dbw.close();
                                                        }

                                                        //clear the variables to be reused on next transmission
                                                        Constants.setNumberMessages(0);
                                                        Constants.setDecryptionMessage("");

                                                        i.putExtra("RECEIVER_PHONENUMBER", originatingPhoneNumber);
                                                        i.putExtra("MYPHONENUMBER", myPhoneNumber);
                                                        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                                                        context.startActivity(i);

                                                    }catch(Exception e){
                                                        e.printStackTrace();
                                                    }
                                                    }
                                            }
                                            else{
                                                if (protocolId.compareTo("U")==0){
                                                    //update my keys
                                                    Utils u = new Utils();
                                                    String nonceGenerated = u.generateNonce();
                                                    Constants.setMyNonce(nonceGenerated);

                                                    Log.i("I:", "U: On update, update my nonce to start the protocol with:"+ nonceGenerated);

                                                    //TODO: delete all messages from incoming number (originatingPhoneNumber)
                                                    SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);
                                                    SQLiteDatabase db = mDbHelper.getReadableDatabase();

                                                    int count = db.delete(
                                                            SMSEncryptionContract.Messages.TABLE_NAME,
                                                            SMSEncryptionContract.Messages.COLUMN_RECEIVER_PHONENUMBER + "="+ originatingPhoneNumber +
                                                                    " OR "+ SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER + "=" +
                                                                    originatingPhoneNumber,
                                                            null
                                                    );

                                                    if (db!=null){
                                                        db.close();
                                                    }

                                                    String messageToSend = nonceGenerated;
                                                    messageToSend = messageToSend + ":P:0";

                                                    //clear the variables to be reused on next transmission
                                                    Constants.setNumberMessages(0);
                                                    Constants.setDecryptionMessage("");

                                                    SmsManager smsManager = SmsManager.getDefault();

                                                    PendingIntent sentIntent = PendingIntent.getBroadcast(context, 0,
                                                            intent, 0);
                                                    context.getApplicationContext().registerReceiver(
                                                            new SmsReceiver(),
                                                            new IntentFilter(SENT_SMS_FLAG));
                                                    smsManager.sendTextMessage(originatingPhoneNumber, null,
                                                            messageToSend , sentIntent, null);

                                                    Toast.makeText(context, messageToSend, Toast.LENGTH_SHORT).show();

                                                }
                                            }
                                        }

                                    }
                                }

                            }

                            if (sessionErrorKey) {
                                Toast.makeText(context, errorReason, Toast.LENGTH_SHORT).show();
                            }

                        }
                    }
                }
            }
        }

    public String encryptSymmetric(byte[] message, byte[] key) {

        byte[] encrypted = null;

        try{
            SecretKey secretKeySpec = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            encrypted = cipher.doFinal(message);

            String strEncrypted = new String(Hex.encodeHex(encrypted));
            return strEncrypted;
        }
        catch(NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String encryptAsymmetric(byte[] message, PublicKey key) {

        byte[] encrypted = null;

        try{
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = cipher.doFinal(message);
            String strEncrypted = new String(Hex.encodeHex(encrypted));
            byte[] bytesEncMessage = Hex.decodeHex(strEncrypted.toCharArray());
            int i =bytesEncMessage.length;
            return strEncrypted;
        }
        catch(NoSuchAlgorithmException e){
            e.printStackTrace();
            return null;
        } catch (BadPaddingException e) {
            e.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }catch (DecoderException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String decryptSymmetrically(byte[] message, byte[] key){

        byte[] clearText = null;
        try {

            byte[] input = Base64.decodeBase64(message);
            SecretKey secretKeySpec = new SecretKeySpec(key, "AES");

            byte[] keyBytes = secretKeySpec.getEncoded();
            String strKeyBytes = new String(Hex.encodeHex(keyBytes));

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            clearText = cipher.doFinal(input);

            return new String(clearText);
        }
        catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public String decryptSymmetric(byte[] message, byte[] key)  {

        byte[] clearText = null;

        try {

            SecretKey secretKeySpec = new SecretKeySpec(key, "AES");

            byte[] keyBytes = secretKeySpec.getEncoded();
            String strKeyBytes = new String(Hex.encodeHex(keyBytes));

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            clearText = cipher.doFinal(message);

            return new String(Hex.encodeHex(clearText));
        }
        catch( Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public String decryptAsymmetric(byte[] message, PrivateKey key)  {

        String clearText = "";
        byte[] decryptedBytes;
        try {
            String strEncrypted = new String(Hex.encodeHex(message));

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedBytes = cipher.doFinal(message);
            return new String(Hex.encodeHex(decryptedBytes));
        }
        catch( Exception e){
            e.printStackTrace();
            return null;
        }
    }


    public byte[] generateHashFromNonces(String hisNonce, String myNonce) throws
            UnsupportedEncodingException, NoSuchAlgorithmException{

        byte[] saltHash = (myNonce + hisNonce).getBytes("UTF-8");

        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        saltHash = sha.digest(saltHash);
        saltHash = Arrays.copyOf(saltHash, 16); // use only first 128 bit

        return saltHash;
    }
}
