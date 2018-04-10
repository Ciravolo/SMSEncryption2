package com.example.smsencryption.smsencryption;

import android.app.PendingIntent;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import com.example.smsencryption.smsencryption.database.SMSEncryptionContract;
import com.example.smsencryption.smsencryption.database.SMSEncryptionDbHelper;

import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SendMessageActivity extends AppCompatActivity {

    private String sessionKey = "";
    private String phoneNumber = "";
    private String myPhoneNumber = "";

    private Button btnSendMessage;
    private EditText txtMessageToSend;

    private String SENT = "SMS_SENT";
    private String DELIVERED = "SMS_DELIVERED";

    private ListView list;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_send_message);

        Bundle bundle = this.getIntent().getExtras();
        sessionKey = bundle.getString("SESSION_KEY");
        phoneNumber = bundle.getString("RECEIVER_PHONENUMBER");
        myPhoneNumber = bundle.getString("MYPHONENUMBER");

        btnSendMessage = (Button) findViewById(R.id.btnSendMessage);
        txtMessageToSend = (EditText) findViewById(R.id.txtMessageToSend);

        btnSendMessage.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                if (txtMessageToSend.getText().toString().compareTo("")==0){
                    //send an alarm saying to enter a text first
                    AlertDialog alertDialog = new AlertDialog.Builder(SendMessageActivity.this).create();
                    alertDialog.setTitle("Alert");
                    alertDialog.setMessage("Please insert a message.");
                    alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                            new DialogInterface.OnClickListener() {
                                public void onClick(DialogInterface dialog, int which) {
                                    dialog.dismiss();
                                }
                            });
                    alertDialog.show();
                }
                else{
                    //send the message encrypted with the session key to the receiver
                    if ((sessionKey.compareTo("")!=0)&&(phoneNumber.compareTo("")!=0)){

                        //obtain my phone number
                        TelephonyManager tMgr = (TelephonyManager)getSystemService(Context.TELEPHONY_SERVICE);
                        String myPhoneNumber = tMgr.getLine1Number();

                        //if the parameters have been set correctly then send the message
                        sendEncryptedSMS(phoneNumber, sessionKey, txtMessageToSend.getText().toString(), myPhoneNumber);
                    }
                }


            }
        });

        SMSEncryptionDbHelper mDbHelper1 = new SMSEncryptionDbHelper(getBaseContext());
        SQLiteDatabase db1 = mDbHelper1.getReadableDatabase();

        String[] projection1 = {
                SMSEncryptionContract.Messages._ID,
                SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER,
                SMSEncryptionContract.Messages.COLUMN_RECEIVER_PHONENUMBER,
                SMSEncryptionContract.Messages.COLUMN_CONTENT,
                SMSEncryptionContract.Messages.COLUMN_TIME
        };

        // Filter results WHERE "title" = 'My Title'

        Log.i("phoneNumber query:", phoneNumber);
        Log.i("myphoneNumber query:", myPhoneNumber);


        String selection = SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER + " IN ( ? , ? ) ";
        String[] selectionArgs = { phoneNumber , myPhoneNumber};

        Cursor cursor1 = db1.query(
                SMSEncryptionContract.Messages.TABLE_NAME,// The table to query
                projection1,                               // The columns to return
                selection,                                // The columns for the WHERE clause
                selectionArgs,                            // The values for the WHERE clause
                null,                                     // don't group the rows
                null,                                     // don't filter by row groups
                SMSEncryptionContract.Messages.COLUMN_TIME+" ASC"    // The sort order
        );

        List itemSenderPhoneNumber = new ArrayList<>();
        List itemMsgs = new ArrayList<>();
        List itemTime = new ArrayList<>();

        while(cursor1.moveToNext()) {
            String senderPhoneNumber = cursor1.getString(cursor1.getColumnIndex(SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER));
            Log.i("i:", "sender:"+senderPhoneNumber);
            itemSenderPhoneNumber.add(senderPhoneNumber);

            String msg = cursor1.getString(cursor1.getColumnIndex(SMSEncryptionContract.Messages.COLUMN_CONTENT));
            Log.i("i:", "message: "+msg);
            itemMsgs.add(msg);

            String time = cursor1.getString(cursor1.getColumnIndex(SMSEncryptionContract.Messages.COLUMN_TIME));
            Log.i("i:", "message: "+time);
            itemTime.add(time);
        }
        cursor1.close();

        list = (ListView)findViewById(R.id.messages_view);

        List<Message> listMessages = new ArrayList<Message>();

        for (int i =0; i<itemMsgs.size(); i++){
            listMessages.add(new Message(itemMsgs.get(i).toString(), itemSenderPhoneNumber.get(i).toString(), itemTime.get(i).toString()));
        }

        MessageAdapter adapter = new MessageAdapter(this, listMessages);
        list.setAdapter(adapter);

    }

    @Override
    protected void onNewIntent(Intent intent){
        Bundle extras = intent.getExtras();
        Intent msgIntent = new Intent(this, SendMessageActivity.class);
        msgIntent.putExtras(extras);
        startActivity(msgIntent);
        finish();
        return;
    }



    private void sendEncryptedSMS(String phoneNumber, String sessionKey, String plainText, String myPhoneNumber){

        Utils u = new Utils();

        Intent sendReceiverPhoneNumber = new Intent("sendReceiverPhone");
        sendReceiverPhoneNumber.putExtra("receiverphonenumber", phoneNumber);
        sendBroadcast(sendReceiverPhoneNumber);

        try{

            byte[] inputByte = plainText.getBytes("UTF-8");

           // byte[] plainTextBytes = Base64.encode(plainText.getBytes(), Base64.DEFAULT);
            byte[] sessionKeyBytes = Hex.decodeHex(sessionKey.toCharArray());

            String messageEncrypted = encryptSymmetrically(inputByte, sessionKeyBytes);
            messageEncrypted = messageEncrypted+":M";

            Log.i("SEND ON ENC:", messageEncrypted);

            PendingIntent sentPI = PendingIntent.getBroadcast(this, 0,
                new Intent(SENT), PendingIntent.FLAG_ONE_SHOT);

            PendingIntent deliveredPI = PendingIntent.getBroadcast(this, 0,
                new Intent(DELIVERED), PendingIntent.FLAG_ONE_SHOT);

            SmsManager sms = SmsManager.getDefault();
            Toast.makeText(getApplicationContext(), "Phone number to send:"+phoneNumber, Toast.LENGTH_LONG).show();

            SMSEncryptionDbHelper mDbHelper = new SMSEncryptionDbHelper(getBaseContext());
            SQLiteDatabase dbw = mDbHelper.getWritableDatabase();
            ContentValues values = new ContentValues();

            values.put(SMSEncryptionContract.Messages.COLUMN_SENDER_PHONENUMBER, myPhoneNumber);
            values.put(SMSEncryptionContract.Messages.COLUMN_RECEIVER_PHONENUMBER, phoneNumber);
            values.put(SMSEncryptionContract.Messages.COLUMN_CONTENT, plainText);
            values.put(SMSEncryptionContract.Messages.COLUMN_TIME, u.getDateTime());

            //Insert the row
            long newRowId = dbw.insert(SMSEncryptionContract.Messages.TABLE_NAME, null, values);

            sms.sendTextMessage(phoneNumber, null, messageEncrypted, sentPI, deliveredPI);

            //recall the activity to show the messages refreshed
            Intent i = new Intent(this, SendMessageActivity.class);

            i.putExtra("SESSION_KEY", sessionKey);
            i.putExtra("RECEIVER_PHONENUMBER", phoneNumber);
            i.putExtra("MYPHONENUMBER", myPhoneNumber);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            this.startActivity(i);

        } catch(Exception e){
            Toast.makeText(getApplicationContext(), "SMS Failed, please try again later", Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }

    }

    public String encryptSymmetrically(byte[] message, byte[] key) {

        byte[] encrypted = null;

        try{
            SecretKey secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            encrypted = cipher.doFinal(message);
            String strEncrypted = new String(Base64.encode(encrypted, Base64.DEFAULT));
            Log.i("Step 1: After enc:", strEncrypted);
            return strEncrypted;

        } catch(NoSuchAlgorithmException e){
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

}
