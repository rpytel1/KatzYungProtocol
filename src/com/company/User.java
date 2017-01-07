package com.company;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static java.util.Collections.*;

/**
 * Created by Rafal on 2016-12-29.
 */
public class User {

    PrivateKey privateKey;
    PublicKey publicKey;
    Map<String, PublicKey> publicKeyMap = new HashMap<>();
    String userID = new String();
    String r = new String();
    List<String> possibleUsers = new ArrayList<>(); //Powinno sie dodać zbior dostepnych userow
    List<Nonce> nonceList = new ArrayList<>();
    Nonce myNonce;
    Integer Z;
    Random random = new Random();
    List<Integer> otherZ = new ArrayList<>();
    Long sessionKey = new Long(1);

    static Integer K = 5;//Stopien zaszyfrowania
    static Integer Q = 7919;//
    static Integer G = 7207;

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

    public Map<String, PublicKey> getPublicKeyMap() {
        return publicKeyMap;
    }

    public void setPublicKeyMap(Map<String, PublicKey> publicKeyMap) {
        this.publicKeyMap = publicKeyMap;
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
        int s = random.nextInt(Q);
        //Compute Z
        Z = 1;
        for (int i = 0; i < s; i++) {
            Z = (Z * G) % Q;
        }


        String sigma = "1" + (Z);
        sort(nonceList);
        for (Nonce nonce : nonceList) {
            sigma += nonce.toString();
        }
        try {


            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey, new SecureRandom());
            byte[] arr = sigma.getBytes();
            signature.update(arr);
            byte[] sigBytes = signature.sign();
            String sig = new String(Base64.getEncoder().encode(sigBytes));

            message += userID + "1" + Z.toString() + sig;

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
        int zStartIndex = 0, zEndIndex = 0;
        char one = '1';
        String Zj = new String();
        for (String userId : possibleUsers) {
            if (userId.equals(message.substring(0, userId.length())) && (message.charAt(userId.length()) == one)) {
                firstCondition = true;
                secondCondition = true;
                idUser = userId;
                zStartIndex = userId.length() + 1;
                zEndIndex = message.length() - 172;
                Zj = message.substring(zStartIndex, zEndIndex);
            }
        }
        try {

            // Collections.sort(nonceList);
            String nonceStr = new String();
            for (Nonce nonce : nonceList) {
                nonceStr += nonce.toString();
            }


            String verify = "1" + Zj + nonceStr;
            Signature signature = Signature.getInstance("SHA1withRSA");
            PublicKey pubKey = publicKeyMap.get(idUser);
            signature.initVerify(pubKey);
            String sigma = message.substring(zEndIndex);

            byte[] arr = Base64.getDecoder().decode(sigma.getBytes());
            ;
            signature.update(verify.getBytes());
            boolean result = signature.verify(arr);

            System.out.println(result);

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
        // Collections.sort(nonceList);
        String nonceStr = new String();
        for (Nonce nonce : nonceList) {
            nonceStr += nonce.toString();
        }
        String sig = "2" + X + nonceStr;

        try {

            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateKey, new SecureRandom());
            byte[] toSign = sig.getBytes();
            signature.update(toSign);
            byte[] signed = signature.sign();
            String sgm1 = new String(Base64.getEncoder().encode(signed));
            message = userID + "2" + X + sgm1;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return message;
    }

    //TODO: also test
    public void reciveX(String message) {
        boolean firstCondition = false, secondCondition = false, thirdCondition = false;
        String idUser = new String();
        int xStartIndex = 0, xEndIndex = 0;
        char two = '2';
        String Xj = new String();
        for (String userId : possibleUsers) {
            if (userId.equals(message.substring(0, userId.length())) && (message.charAt(userId.length()) == two)) {
                firstCondition = true;
                secondCondition = true;
                idUser = userId;

                xStartIndex = userId.length() + 1;
                xEndIndex = message.length() - 172;
                Xj = message.substring(xStartIndex, xEndIndex);
            }
        }
        try {
            String nonceStr = new String();
            // Collections.sort(nonceList);
            for (Nonce nonce : nonceList) {
                nonceStr += nonce.toString();
            }

            String verify = "2" + Xj + nonceStr;

            Signature signature = Signature.getInstance("SHA1withRSA");
            PublicKey pubKey = publicKeyMap.get(idUser);
            signature.initVerify(pubKey);
            String sigma = message.substring(xEndIndex);

            byte[] arr = Base64.getDecoder().decode(sigma.getBytes());

            signature.update(verify.getBytes());
            boolean result = signature.verify(arr);
            System.out.println(result);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    //TODO: ask if it is correct way, and then how to encrypt and decrypt message
    public void computeSessionKey() {
        Integer n = 0;
        sort(otherZ);
        for (int i = 0; i < otherZ.size() - 1; i++) {
            Integer si1 = getSi(otherZ.get(i));
            Integer si2 = getSi(otherZ.get(i + 1));
            n = n + si1 * si2;
        }
        Integer si1 = getSi(otherZ.get(0));
        Integer si2 = getSi(otherZ.get(otherZ.size() - 1));
        n = n + si1 * si2;
        n = n % Q;
        for (int i = 0; i < n; i++) {
            sessionKey = (sessionKey * G) % Q;
        }

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

    public String getX(Integer k) {
        //TODO: check if it is correct way to compute X
        sort(otherZ);
        int index = otherZ.indexOf(k);
        int prevIndex = index - 1;
        int aftIndex = index + 1;
        if (prevIndex < 0) {
            prevIndex = otherZ.size() - 1;
        }
        if (aftIndex > otherZ.size() - 1) {
            aftIndex = 0;
        }
        Integer Z1 = otherZ.get(prevIndex);
        Integer Z2 = otherZ.get(aftIndex);

        int s2 = getSi(Z2);
        int n = Q - 1 - s2;
        if (n < 0) {
            n += Q;
        }
        Integer otherZ2 = 1;
        for (int i = 0; i < n; i++) {
            otherZ2 = (otherZ2 * G) % Q;
        }
        Integer Xi = Z1 * otherZ2;
        Integer copy = Xi;
        Integer pow = Integer.parseInt(r, 2);
        ;
        for (int i = 0; i < pow; i++) {
            Xi = (Xi * copy) % Q;
        }

        return Xi.toString();
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
