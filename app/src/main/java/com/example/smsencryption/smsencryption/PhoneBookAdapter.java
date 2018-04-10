package com.example.smsencryption.smsencryption;


import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.telephony.SmsManager;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.ListAdapter;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;

import static android.app.PendingIntent.FLAG_ONE_SHOT;

public class PhoneBookAdapter extends BaseAdapter implements ListAdapter{

    private Context mContext;
    private List<PhoneBook> mListPhoneBook;
    //onClickInAdapter onClickInAdapter;

    public PhoneBookAdapter(Context context, List<PhoneBook> list){
        mContext = context;
        mListPhoneBook = list;
    }

    @Override
    public int getCount() {
        return mListPhoneBook.size();
    }

    @Override
    public Object getItem(int position) {
        return mListPhoneBook.get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        PhoneBook entry = mListPhoneBook.get(position);

        if (convertView == null){
            LayoutInflater inflater = LayoutInflater.from(mContext);
            convertView = inflater.inflate(R.layout.phonebook_row, null);
        }

        TextView tvName = (TextView) convertView.findViewById(R.id.txtContactName);
        tvName.setText(entry.getmName());

        TextView tvPhoneNUmber = (TextView) convertView.findViewById(R.id.txtPhoneNumber);
        tvPhoneNUmber.setText(entry.getmPhone());

        //Set actions for the button to establish the session key

        Button establishSessionKeyBtn = (Button) convertView.findViewById(R.id.sessionkey_btn);

        Button sendMessageBtn = (Button) convertView.findViewById(R.id.send_message_btn);

        establishSessionKeyBtn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                //passing the data to the activity to start the session key establishment
                Intent i = new Intent(mContext, PhoneBookActivity.class);
                i.putExtra("SESSION_USERNAME", entry.getmName());
                i.putExtra("SESSION_PHONE", entry.getmPhone());
                mContext.startActivity(i);
                notifyDataSetChanged();
            }

        });

        sendMessageBtn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v){
                //passing the data to the activity to start the session key establishment
                Intent i = new Intent(mContext, PhoneBookActivity.class);
                i.putExtra("MESSAGE_USERNAME", entry.getmName());
                i.putExtra("MESSAGE_PHONE", entry.getmPhone());
                mContext.startActivity(i);
                notifyDataSetChanged();
            }

        });

        return convertView;
    }

    //interface to send the data to the activity below
    public interface OnClickInAdapter{
        public void onClickInAdapter(String content);
    }


/*
    private void sendSMS(String contactName, String phoneNumber, String encryptedMessage){

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

            //before sending the message I append the step
            String m = encryptedMessage;

            //testing that the service center address parameter can be used as a contact name parameter
            sms.sendTextMessage(phoneNumber, contactName, m, sentPI, deliveredPI);
        } catch(Exception e){
            Toast.makeText(getApplicationContext(), "SMS Failed, please try again later", Toast.LENGTH_LONG).show();
            e.printStackTrace();
        }
    }
*/
}
