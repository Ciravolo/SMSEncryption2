package com.example.smsencryption.smsencryption;

import android.app.PendingIntent;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
import android.os.NetworkOnMainThreadException;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.telephony.SmsManager;
import android.util.Log;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.spec.SecretKeySpec;

public class GenerateQRCodeActivity extends AppCompatActivity {

    ImageView imageViewQRCode;
    TextView txtTest;
    private String contactName;
    private String phoneNumber;

    String SENT = "SMS_SENT";
    String DELIVERED = "SMS_DELIVERED";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_generate_qrcode);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        imageViewQRCode = (ImageView) findViewById(R.id.imageViewQRCode);

        Bundle bundle = this.getIntent().getExtras();
        contactName = bundle.getString("NAME");
        phoneNumber = bundle.getString("PHONENUMBER");

        try {
            String randomSeed = generateRandomizedString1024Bits();
            setQRCode(randomSeed);

            Constants.setW(randomSeed);

            //TODO: sending by text message the W to test, but it should be from Qrcode exchange
            sendSMS(phoneNumber, contactName,randomSeed+":W");

        }
        catch(Exception e){
            e.printStackTrace();
        }

    }


    public String generateRandomizedString1024Bits() throws NoSuchAlgorithmException, UnsupportedEncodingException{
        SecureRandom random = new SecureRandom();
        //TODO: uncomment this line to generate a QR Code of 1024 bits
        //byte[] bytes = new byte[128];

        byte[] bytes = new byte[16];

        random.nextBytes(bytes);
        String randomGeneratedString = new String(Hex.encodeHex(bytes));
        randomGeneratedString.replace('+','-').replace('/','_');
        return randomGeneratedString;
    }


    public String generateRandomSeed(){
        Random r = new Random(System.currentTimeMillis());
        int number = 10000 + r.nextInt(20000);
        return String.valueOf(number);
    }

    public void setQRCode(String qrText){

        QRCodeWriter writer = new QRCodeWriter();

        try {
            BitMatrix bitMatrix = writer.encode(qrText, BarcodeFormat.QR_CODE, 1024, 1024);

            int width = bitMatrix.getWidth();
            int height = bitMatrix.getHeight();
            Bitmap bmp = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565);
            for (int x = 0; x < width; x++) {
                for (int y = 0; y < height; y++) {
                    bmp.setPixel(x, y, bitMatrix.get(x, y) ? Color.BLACK : Color.WHITE);
                }
            }

            imageViewQRCode.setImageBitmap(bmp);

        } catch (WriterException e) {
            e.printStackTrace();
        }
    }


    private void sendSMS(String phoneNumber, String contactName, String message){

        Intent sendPhoneNumberIntent = new Intent("my.action.string");
        sendPhoneNumberIntent.putExtra("contactname", contactName);
        sendBroadcast(sendPhoneNumberIntent);

        PendingIntent sentPI = PendingIntent.getBroadcast(this, 0,
                new Intent(SENT), PendingIntent.FLAG_ONE_SHOT);

        PendingIntent deliveredPI = PendingIntent.getBroadcast(this, 0,
                new Intent(DELIVERED), PendingIntent.FLAG_ONE_SHOT);

        try{
            SmsManager sms = SmsManager.getDefault();
            Toast.makeText(getApplicationContext(), "Phone number to send:"+phoneNumber, Toast.LENGTH_LONG).show();

            sms.sendTextMessage(phoneNumber, contactName, message, sentPI, deliveredPI);
        } catch(Exception e){
            Toast.makeText(getApplicationContext(), "SMS Failed, please try again later", Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }
    }

}
