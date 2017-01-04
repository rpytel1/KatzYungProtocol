package com.company;

/**
 * Created by Rafal on 2016-12-31.
 */
public class Nonce implements Comparable {
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

    @Override
    public int compareTo(Object o) {
        Nonce comp = (Nonce) o;
        Integer compID = new Integer(comp.getUserID());
        Integer ID = new Integer(this.getUserID());
        if (compID < ID) {
            return -1;
        }
        if (compID == ID) {
            return 0;
        } else
            return -1;

    }
}
