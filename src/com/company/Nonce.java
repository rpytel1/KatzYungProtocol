package com.company;

/**
 * Created by Rafal on 2016-12-31.
 */
public class Nonce {
    String userID;
    String r;

    public Nonce(String userID, String r) {
        this.userID = userID;
        this.r = r;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getR() {
        return r;
    }

    public void setR(String r) {
        this.r = r;
    }

    public String toString() {
        return userID.toString() + r.toString();
    }
}
