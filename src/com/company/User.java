package com.company;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/**
 * Created by Rafal on 2016-12-29.
 */
public class User {

    PrivateKey myKey;
    Map<String, PublicKey> otherUsersKey = new HashMap<>();//should be dictionary with user ids and it public keys
    String userID=new String();
    String r = new String();


    List<String> possibleUsers = new ArrayList<>(); //Powinno sie dodać zbior dostepnych userow
    List<Nonce> nonceList = new ArrayList<>();
    Nonce myNonce;
    Integer Z;
    Random random = new Random();
    List<Integer> otherZ = new ArrayList<>();
    Long sessionKey=null;

    static Integer K = 5;//Stopien zaszyfrowania
    static Integer Q = 3;//
    static Integer G = 5;

    public User() {
        for (int i = 0; i < K; i++) {
            Integer n = random.nextInt(10);
            userID += n.toString();
        }
    }

    public String getR() {
        return r;
    }

    public void setR() {

        for (int i = 0; i < K; i++) {
            Integer n = random.nextInt(2);
            r += n.toString();
        }
        myNonce = new Nonce(userID, r);
        nonceList.add(myNonce);
    }

    public Map<String, PublicKey> getOtherUsersKey() {
        return otherUsersKey;
    }

    public void setOtherUsersKey(Map<String, PublicKey> otherUsersKey) {
        this.otherUsersKey = otherUsersKey;
    }

    public PrivateKey getMyKey() {
        return myKey;
    }

    public void setMyKey(PrivateKey myKey) {
        this.myKey = myKey;
    }


    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public List<Nonce> getNonceList() {
        return nonceList;
    }

    public void setNonceList(List<Nonce> nonceList) {
        this.nonceList = nonceList;
    }

    public List<String> getPossibleUsers() {
        return possibleUsers;
    }

    public void setPossibleUsers(List<String> possibleUsers) {
        this.possibleUsers = possibleUsers;
    }

    public void addNonce(String message) {
        int rStart = message.length() - K;
        String nonceR = message.substring(rStart, message.length());
        String nonceUID = message.substring(0, rStart - 1);

        Nonce nonce = new Nonce(nonceUID, nonceR);
        nonceList.add(nonce);
    }

    //STEP 2
    public String computeSignature() {
        String message = new String();
        int s = random.nextInt(Q) + 1;
        //Compute Z
        Z = 1;
        for (int i = 0; i < s; i++) {
            Z = (Z * G) % Q;
        }


        String sigma = "1" + (Z);

        for (Nonce nonce : nonceList) {
            sigma += nonce.toString();
        }
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            cipher.init(Cipher.ENCRYPT_MODE, otherUsersKey.get(this.userID));

            byte[] SignSigm = cipher.doFinal(sigma.getBytes());
            System.out.println(SignSigm);
            Cipher cipher2=Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher2.init(Cipher.DECRYPT_MODE,myKey);
            byte[]decryptSign=cipher2.doFinal();
            System.out.println(SignSigm.toString()+":"+decryptSign.toString());

            message += userID + "1" + Z.toString().length() + Z + SignSigm;//optimzed just for Z<999999999

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return message;
    }

    //STEP 3A
    //TODO:check if it works!!
    public void recieveSignature(String message) {
        boolean firstCondition = false, secondCondition = false, thirdCondition = false;
        String idUser = new String();
        Integer zSize = 0;
        int zStartIndex = 0, zEndIndex = 0;
        char one = '1';
        String Zj = new String();
        for (String userId : possibleUsers) {
            if (userId.equals(message.substring(0, userId.length())) && (message.charAt(userId.length()) == one)) {
                firstCondition = true;
                secondCondition = true;
                idUser = userId;
                zSize = Character.getNumericValue(message.charAt(userId.length() + 1));
                zStartIndex = userId.length() + 2;
                zEndIndex = zStartIndex + zSize;
                Zj = message.substring(zStartIndex, zEndIndex);
            }
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            PublicKey publicKey = otherUsersKey.get(idUser);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            String sigma = message.substring(zEndIndex );
            byte[] decryptedSigma = cipher.doFinal(sigma.getBytes());
            String decSigma = new String(decryptedSigma);
            String nonce = nonceList.toString();
            String verify = "1" + Zj + nonce;

            if (decSigma.equals(verify)) {
                System.out.println("third condition fullfiled!");
                thirdCondition = true;
            }
            otherZ.add(new Integer(Zj));


        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    //STEP 3B
    public String sendX() {
        //
        String X = getX(Z);
        String message = new String();
        String sig = "2" + X + nonceList.toString();
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");


            cipher.init(Cipher.ENCRYPT_MODE, myKey);
            byte[] sigma = cipher.doFinal(sig.getBytes());
            message = userID + "2" + X.length() + X + sigma.toString();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return message;
    }
//TODO: also test
    public void reciveX(String message) {
        boolean firstCondition = false, secondCondition = false, thirdCondition = false;
        String idUser = new String();
        Integer xSize = 0;
        int xStartIndex = 0, xEndIndex = 0;
        char two = '2';
        String Xj = new String();
        for (String userId : possibleUsers) {
            if (userId.equals(message.substring(0, userId.length())) && (message.charAt(userId.length()) == two)) {
                firstCondition = true;
                secondCondition = true;
                idUser = userID;
                xSize = new Integer(message.charAt(userId.length() + 1));
                xStartIndex = userID.length() + 2;
                xEndIndex = xStartIndex + xSize;
                Xj = message.substring(xStartIndex, xEndIndex);
            }
        }
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            PublicKey publicKey = otherUsersKey.get(idUser);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);

            String sigma = message.substring(xEndIndex + 1);
            byte[] decryptedSigma = cipher.doFinal(sigma.getBytes());
            String decSigma = new String(decryptedSigma);
            String nonce = nonceList.toString();
            String verify = "1" + Xj + nonce;

            if (decSigma.equals(verify)) {
                System.out.println("third condition fulfiled!");
                thirdCondition = true;
            }


        } catch (Exception e) {
            e.printStackTrace();
        }

    }
//TODO: ask if it is correct way, and then how to encrypt and decrypt message
    public void computeSessionKey() {
        Integer n=0;
        Collections.sort(otherZ);
        for (int i = 0; i < otherZ.size() - 1; i++) {
            Integer si1 = getSi(otherZ.get(i));
            Integer si2 = getSi(otherZ.get(i + 1));
            n=n+si1*si2;
        }
        Integer si1=getSi(otherZ.get(0));
        Integer si2=getSi(otherZ.get(otherZ.size()-1));
        n=n+si1*si2;
        sessionKey= (long)Math.pow(G,n);
    }




    public Integer getSi(Integer Zi) {
        boolean undone = true;
        int si = 1;
        int m = G % Q;
        while (undone) {
            if (m == Zi) {
                undone = false;
            } else {
                m = (m * G) % Q;
                si++;
            }
        }
        return si;
    }

    public String getX(int k) {
        //TODO: check if it is correct way to compute X
        Integer y = k - 1, zz = k + 1;
        if (k == 1) {
            y = Q;
        }
        if (k == Q) {
            zz = 1;
        }
        Integer X = 1;
        Integer R = getIntR();
        for (int i = 0; i < R; i++) {
            X = X * (zz / y) % Q;
        }
        return X.toString();
    }

    public int getIntR() {
        char[] cA = r.toCharArray();
        int result = 0;
        for (int i = cA.length - 1; i >= 0; i--) {
            if (cA[i] == '1') result += Math.pow(2, cA.length - i - 1);
        }
        return result;
    }
}
