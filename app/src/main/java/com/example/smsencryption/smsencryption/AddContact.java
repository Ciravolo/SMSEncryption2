package com.example.smsencryption.smsencryption;

import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.app.Activity;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.AppCompatButton;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

public class AddContact extends AppCompatActivity {

    private View btnNext;
    private EditText txtPhoneNumber;
    private EditText txtContactName;

    private String phoneNumber;
    private String contactName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_add_contact);

        btnNext = findViewById(R.id.btnNext);

        txtPhoneNumber = (EditText) findViewById(R.id.txtPhoneNumber);
        txtContactName = (EditText) findViewById(R.id.txtContactName);


        btnNext.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                String phoneNumber = txtPhoneNumber.getText().toString();
                String contactName = txtContactName.getText().toString();

                if (phoneNumber.length()>0 && contactName.length()>0){

                    Intent intentStart = new Intent(AddContact.this, QRCodeExchange.class);
                    intentStart.putExtra("NAME", contactName);
                    intentStart.putExtra("PHONENUMBER", phoneNumber);
                    startActivity(intentStart);
                }
                else{

                    new AlertDialog.Builder(AddContact.this)
                            .setTitle("Alert")
                            .setMessage("Please fill the correspondent fields before proceeding.")
                            .setCancelable(false)
                            .setPositiveButton("ok", new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    //close the dialog
                                    dialog.cancel();
                                }
                            }).show();
                }
            }
        });


    }

}
