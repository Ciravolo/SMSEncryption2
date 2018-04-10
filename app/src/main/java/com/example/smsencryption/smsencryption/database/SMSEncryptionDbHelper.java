package com.example.smsencryption.smsencryption.database;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import static com.example.smsencryption.smsencryption.database.SMSEncryptionContract.SQL_CREATE_ENTRIES_DIRECTORY;
import static com.example.smsencryption.smsencryption.database.SMSEncryptionContract.SQL_CREATE_ENTRIES_MESSAGES;
import static com.example.smsencryption.smsencryption.database.SMSEncryptionContract.SQL_DELETE_ENTRIES_DIRECTORY;
import static com.example.smsencryption.smsencryption.database.SMSEncryptionContract.SQL_DELETE_ENTRIES_MESSAGES;

/**
 * Created by joana on 8/19/17.
 */

public class SMSEncryptionDbHelper extends SQLiteOpenHelper{
    public static final int DATABASE_VERSION = 1;
    public static final String DATABASE_NAME = "Directory.db";

    public SMSEncryptionDbHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(SQL_CREATE_ENTRIES_DIRECTORY);
        db.execSQL(SQL_CREATE_ENTRIES_MESSAGES);
    }

    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // This database is only a cache for online data, so its upgrade policy is
        // to simply to discard the data and start over
        db.execSQL(SQL_DELETE_ENTRIES_DIRECTORY);
        db.execSQL(SQL_DELETE_ENTRIES_MESSAGES);
        onCreate(db);
    }
    public void onDowngrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        onUpgrade(db, oldVersion, newVersion);
    }

}
