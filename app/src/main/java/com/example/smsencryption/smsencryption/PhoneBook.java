package com.example.smsencryption.smsencryption;

/**
 * Created by joana on 6/28/17.
 */

public class PhoneBook {

    private String mName;
    private String mPhone;

    public PhoneBook(String mName, String mPhone){
        this.mName = mName;
        this.mPhone = mPhone;
    }

    public String getmName() {
        return mName;
    }

    public void setmName(String mName) {
        this.mName = mName;
    }

    public String getmPhone() {
        return mPhone;
    }

    public void setmPhone(String mPhone) {
        this.mPhone = mPhone;
    }
}
