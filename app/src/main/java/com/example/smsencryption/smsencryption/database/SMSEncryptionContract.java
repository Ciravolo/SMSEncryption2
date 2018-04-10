package com.example.smsencryption.smsencryption.database;

import android.provider.BaseColumns;

import java.security.PublicKey;

/**
 * Created by joana on 8/19/17.
 */

public final class SMSEncryptionContract {

    private SMSEncryptionContract(){}

    public static class Directory implements BaseColumns{
        public static final String TABLE_NAME="directory";
        public static final String COLUMN_NAME_NAME = "name";
        public static final String COLUMN_NAME_PHONENUMBER = "phonenumber";
        public static final String COLUMN_NAME_PUBLICKEY = "publickey";
        public static final String COLUMN_LONG_TERM_KEY = "longtermkey";
        public static final String COLUMN_SESSION_KEY = "sessionkey";
    }

    public static class Messages implements BaseColumns{
        public static final String TABLE_NAME="messages";
        public static final String COLUMN_SENDER_PHONENUMBER = "sender";
        public static final String COLUMN_RECEIVER_PHONENUMBER = "receiver";
        public static final String COLUMN_CONTENT = "content";
        public static final String COLUMN_TIME = "time";
    }

    public static final String SQL_CREATE_ENTRIES_DIRECTORY =
            "CREATE TABLE " + Directory.TABLE_NAME + " (" +
                    Directory._ID + " INTEGER PRIMARY KEY," +
                    Directory.COLUMN_NAME_NAME + " TEXT," +
                    Directory.COLUMN_NAME_PHONENUMBER + " TEXT," +
                    Directory.COLUMN_NAME_PUBLICKEY + " TEXT," +
                    Directory.COLUMN_LONG_TERM_KEY + " TEXT," +
                    Directory.COLUMN_SESSION_KEY + " TEXT)";

    public static final String SQL_CREATE_ENTRIES_MESSAGES =
            "CREATE TABLE " + Messages.TABLE_NAME + " (" +
                    Messages._ID + " INTEGER PRIMARY KEY," +
                    Messages.COLUMN_SENDER_PHONENUMBER + " TEXT," +
                    Messages.COLUMN_RECEIVER_PHONENUMBER + " TEXT," +
                    Messages.COLUMN_CONTENT + " TEXT," +
                    Messages.COLUMN_TIME + " TEXT)";

    public static final String SQL_DELETE_ENTRIES_DIRECTORY =
            "DROP TABLE IF EXISTS " + Directory.TABLE_NAME;

    public static final String SQL_DELETE_ENTRIES_MESSAGES =
            "DROP TABLE IF EXISTS " + Messages.TABLE_NAME;


}
