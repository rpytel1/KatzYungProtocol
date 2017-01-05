package com.company;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.*;

/**
 * Created by Rafal on 2016-12-29.
 */
public class User {

    PrivateKey privateKey;
    PublicKey publicKey;

    String userID = new String();
    String r = new String();
    List<String> possibleUsers = new ArrayList<>(); //Powinno sie dodać zbior dostepnych userow
    List<Nonce> nonceList = new ArrayList<>();
    Nonce myNonce;
    Integer Z;
    Random random = new Random();
    List<Integer> otherZ = new ArrayList<>();
    Long sessionKey = null;

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
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }


    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
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
        Collections.sort(nonceList);
        for (Nonce nonce : nonceList) {
            sigma += nonce.toString();
        }
        try {


            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initSign(privateKey, new SecureRandom());
            byte[] arr = sigma.getBytes();
            signature.update(arr);
            byte[] sigBytes = signature.sign();
//            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//
//            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//
//            byte[] SignSigm = cipher.doFinal(sigma.getBytes());
            String sig = new String(Base64.getEncoder().encode(sigBytes));


            message += userID + "1" + Z.toString().length() + Z + sig;//optimized just for Z<999999999

        }
        catch (Exception e) {
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
        try {


//           Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//
//            cipher.init(Cipher.DECRYPT_MODE, privateKey);
//
//            String sigma = message.substring(zEndIndex);
//            byte[]arr=Base64.getDecoder().decode(sigma.getBytes());
//            byte[] decryptedSigma = cipher.doFinal(arr);

          //  Collections.sort(nonceList);
            String nonceStr=new String();
            for (Nonce nonce : nonceList) {
                nonceStr += nonce.toString();
            }


            String verify = "1" + Zj + nonceStr;
            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initVerify(publicKey);
            String sigma = message.substring(zEndIndex);

            byte[] arr = Base64.getDecoder().decode(sigma.getBytes());;
            signature.update(arr);
            signature.verify(verify.getBytes());

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
        Collections.sort(nonceList);
        String nonceStr=new String();
        for(Nonce nonce:nonceList){
            nonceStr+=nonce.toString();
        }
        String sig = "2" + X + nonceStr;
        Cipher cipher = null;
        try {
//            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//            byte[] sigma = cipher.doFinal(sig.getBytes());
//            String sgm=new String(Base64.getEncoder().encode(sigma));

            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initSign(privateKey, new SecureRandom());
            byte[] toSign = sig.getBytes();
            signature.update(toSign);
            byte[] signed = signature.sign();
            String sgm1=new String(Base64.getEncoder().encode(signed));


        //    cipher.init(Cipher.DECRYPT_MODE, privateKey);

//            byte[]arr=Base64.getDecoder().decode(sgm.getBytes());
//
//            byte[] decryptedSigma = cipher.doFinal(arr);
//            String decSigma = new String(decryptedSigma);
//            System.out.println(decSigma.equals(sig));
            message = userID + "2" + X.length() + X + sgm1;

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
//            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//            cipher.init(Cipher.DECRYPT_MODE, privateKey);
//            String sigma = message.substring(xEndIndex);
//            byte[]arr=Base64.getDecoder().decode(sigma.getBytes());
//            byte[] decryptedSigma = cipher.doFinal(arr);


            String nonce = nonceList.toString();
            String verify = "1" + Xj + nonce;

            Signature signature = Signature.getInstance("SHA1withRSA", "BC");
            signature.initVerify(publicKey);
            String sigma = message.substring(xEndIndex);

            byte[] arr = Base64.getDecoder().decode(sigma.getBytes());

            signature.update(arr);
            signature.verify(verify.getBytes());


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    //TODO: ask if it is correct way, and then how to encrypt and decrypt message
    public void computeSessionKey() {
        Integer n = 0;
        Collections.sort(otherZ);
        for (int i = 0; i < otherZ.size() - 1; i++) {
            Integer si1 = getSi(otherZ.get(i));
            Integer si2 = getSi(otherZ.get(i + 1));
            n = n + si1 * si2;
        }
        Integer si1 = getSi(otherZ.get(0));
        Integer si2 = getSi(otherZ.get(otherZ.size() - 1));
        n = n + si1 * si2;
        sessionKey = (long) Math.pow(G, n);
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
