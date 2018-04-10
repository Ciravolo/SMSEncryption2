package com.example.smsencryption.smsencryption;

import android.app.PendingIntent;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.os.Environment;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.ListView;
import android.widget.Toast;

import com.example.smsencryption.smsencryption.database.SMSEncryptionContract;
import com.example.smsencryption.smsencryption.database.SMSEncryptionDbHelper;
import com.github.fafaldo.fabtoolbar.widget.FABToolbarLayout;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static android.app.PendingIntent.FLAG_ONE_SHOT;

public class PhoneBookActivity extends AppCompatActivity {

    private ListView list;
    private FABToolbarLayout morph;
    private String PRIVATE_KEY_FILE="privatekey.txt";
    private String myName="myself";
    private String contactSelectedSK = "";
    private String phoneSelectedSK = "";
    private String contactSelectedMessage = "";
    private String phoneSelectedMessage = "";


    String SENT = "SMS_SENT";
    String DELIVERED = "SMS_DELIVERED";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_phone_book);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        morph = (FABToolbarLayout) findViewById(R.id.fabtoolbar);

        View optionAddContact, optionInfo, optionUpdateKeys;

        optionAddContact = findViewById(R.id.optionAddContact);
        optionInfo = findViewById(R.id.optionInfo);
        optionUpdateKeys = findViewById(R.id.optionUpdateKeys);

        SMSEncryptionDbHelper mDbHelper1 = new SMSEncryptionDbHelper(getBaseContext());

        SQLiteDatabase db1 = mDbHelper1.getReadableDatabase();

        String[] projection1 = {
                SMSEncryptionContract.Directory._ID,
                SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                SMSEncryptionContract.Directory.COLUMN_SESSION_KEY
        };

        Cursor cursor1 = db1.query(
                SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                projection1,                               // The columns to return
                null,                                // The columns for the WHERE clause
                null,                            // The values for the WHERE clause
                null,                                     // don't group the rows
                null,                                     // don't filter by row groups
                null                                      // The sort order
        );

        List itemContacts = new ArrayList<>();
        List itemNames = new ArrayList<>();

        while(cursor1.moveToNext()) {
            String contact = cursor1.getString(cursor1.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER));
            Log.i("i:", "phone number of contact:"+contact);
            itemContacts.add(contact);

            String name = cursor1.getString(cursor1.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_NAME_NAME));
            Log.i("i:", "contact name: "+name);
            itemNames.add(name);
        }
        cursor1.close();

        list = (ListView)findViewById(R.id.listContacts);

        List<PhoneBook> listPhoneBook = new ArrayList<PhoneBook>();

        for (int i =1; i<itemContacts.size(); i++){
            listPhoneBook.add(new PhoneBook(itemNames.get(i).toString(), itemContacts.get(i).toString()));
        }

        PhoneBookAdapter adapter = new PhoneBookAdapter(this,listPhoneBook);
        list.setAdapter(adapter);

        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                morph.show();
            }
        });

        optionInfo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

            }
        });

        optionAddContact.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                //start the protocol with user 1
                Intent intentStart = new Intent(PhoneBookActivity.this, AddContact.class);
                startActivity(intentStart);
                finish();
            }
        });

        optionUpdateKeys.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                TelephonyManager tMgr = (TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE);
                String myPhoneNumber = tMgr.getLine1Number();

                //get all my contacts numbers

                SMSEncryptionDbHelper mDbHelperContacts = new SMSEncryptionDbHelper(getBaseContext());

                SQLiteDatabase dbContacts = mDbHelperContacts.getReadableDatabase();

                String[] projection = {
                        SMSEncryptionContract.Directory._ID,
                        SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                        SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                        SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                        SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                        SMSEncryptionContract.Directory.COLUMN_SESSION_KEY
                };



                String selection = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " != ?";
                String[] selectionArgs = { myPhoneNumber };


                String selectionMyself = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                String[] selectionArgsMyself = { myPhoneNumber };

                Cursor cursorMyself = dbContacts.query(
                        SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                        projection,                               // The columns to return
                        selectionMyself,                                // The columns for the WHERE clause
                        selectionArgsMyself,                            // The values for the WHERE clause
                        null,                                     // don't group the rows
                        null,                                     // don't filter by row groups
                        null                                      // The sort order
                );


                List itemMyPks = new ArrayList<>();

                while(cursorMyself.moveToNext()) {
                    String pk = cursorMyself.getString(
                            cursorMyself.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY));
                    Log.i("I:::::::","My public key before generating new:"+ pk);
                    itemMyPks.add(pk);

                }
                cursorMyself.close();


                Cursor cursorPhoneNumber = dbContacts.query(
                        SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                        projection,                               // The columns to return
                        selection,                                // The columns for the WHERE clause
                        selectionArgs,                            // The values for the WHERE clause
                        null,                                     // don't group the rows
                        null,                                     // don't filter by row groups
                        null                                      // The sort order
                );

                List itemPhoneNumbers = new ArrayList<>();
                List itemNames = new ArrayList<>();

                while(cursorPhoneNumber.moveToNext()) {
                    String itemPhoneNumber = cursorPhoneNumber.getString(
                            cursorPhoneNumber.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER));
                    itemPhoneNumbers.add(itemPhoneNumber);

                    String itemName = cursorPhoneNumber.getString(
                            cursorPhoneNumber.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_NAME_NAME));
                    itemNames.add(itemName);
                }
                cursorPhoneNumber.close();

                if (itemPhoneNumbers.size()>0){

                    for (int i = 0; i< itemPhoneNumbers.size(); i++){

                        //also set my W from the database with this specific user

                        String[] projection2 = {
                                SMSEncryptionContract.Directory._ID,
                                SMSEncryptionContract.Directory.COLUMN_NAME_NAME,
                                SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER,
                                SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY,
                                SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY,
                                SMSEncryptionContract.Directory.COLUMN_SESSION_KEY
                        };

                        // Filter results WHERE "title" = 'My Title'
                        String selection2 = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                        String[] selectionArgs2 = { itemPhoneNumbers.get(i).toString() };

                        Cursor cursorW = dbContacts.query(
                                SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                                projection2,                               // The columns to return
                                selection2,                                // The columns for the WHERE clause
                                selectionArgs2,                            // The values for the WHERE clause
                                null,                                     // don't group the rows
                                null,                                     // don't filter by row groups
                                null                                      // The sort order
                        );

                        List itemLtk = new ArrayList<>();

                        while(cursorW.moveToNext()) {
                            String ltk = cursorW.getString(
                                    cursorW.getColumnIndexOrThrow(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY));
                            itemLtk.add(ltk);
                        }
                        cursorW.close();

                        if (itemLtk.size()>0){

                            Constants.setW(itemLtk.get(0).toString());

                            //update my ltk for this one
                            ContentValues valuesW = new ContentValues();

                            valuesW.put(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY, itemLtk.get(0).toString());

                            // Which row to update, based on the title
                            String selectionUpdateW = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
                            String[] selectionArgsUpdateW = { myPhoneNumber };

                            int count = dbContacts.update(
                                    SMSEncryptionContract.Directory.TABLE_NAME,
                                    valuesW,
                                    selectionUpdateW,
                                    selectionArgsUpdateW);


                        }
                        unsetSessionKey(itemPhoneNumbers.get(i).toString(), getBaseContext());
                        deleteMessagesFrom(itemPhoneNumbers.get(i).toString(), getBaseContext());
                        sendSMS(itemNames.get(i).toString(), itemPhoneNumbers.get(i).toString(), "Update:U");

                    }

                }
                else{
                    //send a notification saying that he doesnt have any contact added so he should add a contact first
                    AlertDialog alertDialog = new AlertDialog.Builder(PhoneBookActivity.this).create();
                    alertDialog.setTitle("Alert");
                    alertDialog.setMessage("Cannot update your keys because you have no shared keys with other users, please add a new contact first.");
                    alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                            new DialogInterface.OnClickListener() {
                                public void onClick(DialogInterface dialog, int which) {
                                    dialog.dismiss();
                                }
                            });
                    alertDialog.show();
                    finish();
                }

                if (dbContacts!=null){
                    dbContacts.close();
                }

            }
        });

        //TODO: check on the database if the keys are already set, if not then create new ones

        TelephonyManager tMgr = (TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE);
        String myPhoneNumber = tMgr.getLine1Number();

        Log.i("my phone number is:", myPhoneNumber);

        if ((myPhoneNumber.compareTo("")!=0)&&(!myPhoneNumber.contains("?"))){

            SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(getBaseContext());

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
            String[] selectionArgs = { myPhoneNumber };

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

            if (itemIds.size()==0) {
            //Keys do not exist so we need to create a pair and save it on the database
                Utils u = new Utils();
                //I get a pair of keys for RSA to set my public key/private key
                Map<String, Object> keys = null;
                try {
                    keys = u.getRSAKeys();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                //Generation of public and private keys on Bob
                PrivateKey privateKey = (PrivateKey) keys.get("private");
                PublicKey publicKey = (PublicKey) keys.get("public");

                Constants.setMyPrivateKey(privateKey);
                Constants.setMyPublicKey(publicKey);

                byte[] bytesMyPublicKey = Constants.getMyPublicKey().getEncoded();
                String strMyPublicKey = new String(Hex.encodeHex(bytesMyPublicKey));

                //TODO: save the private key generated in the device
                //Here the private key is going to be stored in the device
                try{
                    KeyFactory fact = KeyFactory.getInstance("RSA");
                    RSAPrivateKeySpec priv = fact.getKeySpec(privateKey,
                            RSAPrivateKeySpec.class);

                    File newfile = new File(Environment.getExternalStorageDirectory() + File.separator + PRIVATE_KEY_FILE);
                    u.saveToFile(newfile,
                            priv.getModulus(), priv.getPrivateExponent());
                }
                catch(NoSuchAlgorithmException e){
                    e.printStackTrace();
                }catch(IOException e){
                    e.printStackTrace();
                }catch(InvalidKeySpecException e){
                    e.printStackTrace();
                }

                //TODO: record on the database my own public key

                //insert the 2 strings with my phone number on it on the DB

                Log.i("I:", "it is not saved in the database, first time to record my public and private keys.");
                //TODO: It is not saved in the db so save the key of Bob
                //save values on the database

                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_NAME, myName);
                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER, myPhoneNumber);
                values.put(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY, strMyPublicKey);
                values.put(SMSEncryptionContract.Directory.COLUMN_LONG_TERM_KEY, Constants.getW());
                values.put(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY, "none");

                //Insert the row
                long newRowId = dbw.insert(SMSEncryptionContract.Directory.TABLE_NAME, null, values);

                Log.i("I:", "Inserted row with id:"+newRowId);

            }
            else{

                Log.i("i:","use keys already created before");

                Cursor cursor2 = db.query(
                        SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                        projection,                               // The columns to return
                        selection,                                // The columns for the WHERE clause
                        selectionArgs,                            // The values for the WHERE clause
                        null,                                     // don't group the rows
                        null,                                     // don't filter by row groups
                        null                                      // The sort order
                );

                List itemPubKey = new ArrayList<>();

                while(cursor2.moveToNext()) {
                    String pubKey = cursor2.getString(cursor.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_NAME_PUBLICKEY));
                    Log.i("i:", "public key from database:"+pubKey);
                    itemPubKey.add(pubKey);
                }
                cursor2.close();

                //public key is obtained from the database but my private key is on the device saved on a file

                String publicKeyStr = itemPubKey.get(0).toString();

                Log.i("Pub key already set:", publicKeyStr);

                try {
                    byte[] bytesPublicKey = Hex.decodeHex(publicKeyStr.toCharArray());
                    PublicKey myPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytesPublicKey));
                    Constants.setMyPublicKey(myPublicKey);
                    Log.i("i:", "public key is set from the database correctly");

                } catch (Exception e) {
                    e.printStackTrace();
                    Log.i("i:","cannot load the public key from the database");
                }

                //to set the private I do the following: read the file on the device
                Utils u2 = new Utils();

                try {
                    File fileToRead = new File(Environment.getExternalStorageDirectory() + File.separator + PRIVATE_KEY_FILE);
                    PrivateKey privKeyFromDevice = u2.readPrivateKey(fileToRead);

                    if (privKeyFromDevice!=null){
                        //set in my current execution
                        Constants.setMyPrivateKey(privKeyFromDevice);
                    }

                }catch(Exception e){
                    e.printStackTrace();
                }
            }

            if (db!=null){
                db.close();
            }
        }

        Bundle extras = getIntent().getExtras();

        if (extras!=null){

            contactSelectedSK = extras.getString("SESSION_USERNAME");
            phoneSelectedSK = extras.getString("SESSION_PHONE");

            contactSelectedMessage = extras.getString("MESSAGE_USERNAME");
            phoneSelectedMessage = extras.getString("MESSAGE_PHONE");

            if((contactSelectedSK!=null)&&(phoneSelectedSK!=null)){

                Log.i("contactSelectedSK", contactSelectedSK);
                Log.i("phoneSelectedSK", phoneSelectedSK);

                startSessionKeyProtocol(contactSelectedSK, phoneSelectedSK);

            }else{
                if ((contactSelectedMessage!= null)&&(phoneSelectedMessage!=null)){
                    //check if it has a session key established in the database

                    Log.i("contactSelectedMessage", contactSelectedMessage);
                    Log.i("phoneSelectedMessage", phoneSelectedMessage);

                    SMSEncryptionDbHelper mDbHelper2 = new SMSEncryptionDbHelper(getBaseContext());

                    SQLiteDatabase db2 = mDbHelper2.getReadableDatabase();

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
                    String[] selectionArgs = { phoneSelectedMessage };

                    Cursor cursor3 = db2.query(
                            SMSEncryptionContract.Directory.TABLE_NAME,// The table to query
                            projection,                               // The columns to return
                            selection,                                // The columns for the WHERE clause
                            selectionArgs,                            // The values for the WHERE clause
                            null,                                     // don't group the rows
                            null,                                     // don't filter by row groups
                            null                                      // The sort order
                    );

                    List itemSessionKey = new ArrayList<>();

                    while(cursor3.moveToNext()) {
                        String sessionKey = cursor3.getString(cursor3.getColumnIndex(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY));
                        Log.i("i:", "session key from database:"+sessionKey);
                        itemSessionKey.add(sessionKey);
                    }
                    cursor3.close();

                    if (db2!=null){
                        db2.close();
                    }

                    if (itemSessionKey.get(0).toString().compareTo("none")==0){
                        //send notification that it hasnt been set yet
                        AlertDialog alertDialog = new AlertDialog.Builder(PhoneBookActivity.this).create();
                        alertDialog.setTitle("Alert");
                        alertDialog.setMessage("The session key has not been established yet. Please run the session key protocol first.");
                        alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int which) {
                                        dialog.dismiss();
                                        finish();
                                    }
                                });
                        alertDialog.show();
                    }
                    else{
                        //meaning a message could be sent from here using this sessionkey
                        String sessionKey = itemSessionKey.get(0).toString();
                        sendMessageWithSessionKey(sessionKey, phoneSelectedMessage, myPhoneNumber);
                        finish();
                    }
                }
            }

        }

    }

    public void unsetSessionKey(String phoneNumber, Context context){

        SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);

        SQLiteDatabase db = mDbHelper.getReadableDatabase();

        ContentValues values = new ContentValues();

        values.put(SMSEncryptionContract.Directory.COLUMN_SESSION_KEY, "none");

        // Which row to update, based on the title
        String selectionUpdate = SMSEncryptionContract.Directory.COLUMN_NAME_PHONENUMBER + " = ?";
        String[] selectionArgsUpdate = { phoneNumber };

        int count = db.update(
                SMSEncryptionContract.Directory.TABLE_NAME,
                values,
                selectionUpdate,
                selectionArgsUpdate);

        if (db!=null){
            db.close();
        }

        Log.i("I:", "Unset session key: Rows updated:"+count);

    }

    public void deleteMessagesFrom(String phoneNumber, Context context){

        SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(context);
        SQLiteDatabase db = mDbHelper.getReadableDatabase();

        int count = db.delete(
                SMSEncryptionContract.Messages.TABLE_NAME,
                SMSEncryptionContract.Messages.COLUMN_RECEIVER_PHONENUMBER + "="+ phoneNumber +
                        " OR "+ SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER + "=" +
                        phoneNumber,
                null
        );

        if (db!=null){
            db.close();
        }

        Log.i("deleted:", count + "rows");
    }


    public void sendMessageWithSessionKey(String key, String phoneNumber, String myPhoneNumber){

        //start the activity and send the parameters to it
        Intent intentSendMessage = new Intent(PhoneBookActivity.this, SendMessageActivity.class);
        intentSendMessage.putExtra("SESSION_KEY", key);
        intentSendMessage.putExtra("RECEIVER_PHONENUMBER", phoneNumber);
        intentSendMessage.putExtra("MYPHONENUMBER", myPhoneNumber);
        startActivity(intentSendMessage);

    }

    public void startSessionKeyProtocol(String user, String phoneNumber){

        //TODO: start the protocol for the session key establishment
        //send the first message, which is a nonce generated here.

        Utils u = new Utils();
        String nonceGenerated = u.generateNonce();
        Constants.setMyNonce(nonceGenerated);
        nonceGenerated = nonceGenerated+ ":S:0";
        //last indicator :S:0 to say it is the first communication in the session key protocol
        sendSMS(user,phoneNumber,nonceGenerated);
        //finish();
    }


    private void sendSMS(String contactName, String phoneNumber, String message){

        Intent sendPhoneNumberIntent = new Intent("my.action.string");
        sendPhoneNumberIntent.putExtra("contactname", contactName);

        sendBroadcast(sendPhoneNumberIntent);

        PendingIntent sentPI = PendingIntent.getBroadcast(this, 0,
                new Intent(SENT), FLAG_ONE_SHOT);

        PendingIntent deliveredPI = PendingIntent.getBroadcast(this, 0,
                new Intent(DELIVERED), FLAG_ONE_SHOT);

        try{
            SmsManager sms = SmsManager.getDefault();
            Toast.makeText(getApplicationContext(), "Phone number to send:"+phoneNumber, Toast.LENGTH_LONG).show();

            //testing that the service center address parameter can be used as a contact name parameter
            sms.sendTextMessage(phoneNumber, contactName, message, sentPI, deliveredPI);
        } catch(Exception e){
            Toast.makeText(getApplicationContext(), "SMS Failed, please try again later", Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu){
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

}
