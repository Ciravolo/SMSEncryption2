package com.example.smsencryption.smsencryption;

/**
 * Created by joana on 8/30/17.
 */

public class Message {
    private String text;
    private String name;
    private String time;

    public Message(String mText, String mName, String mTime){
        text = mText;
        name = mName;
        time = mTime;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }
}
