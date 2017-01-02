package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class Main {
   static User adam,bobek;

    public static void main(String[] args) {
        try {
            run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void run() throws Exception {
        //1.RSA distribution
        RSADistribution();
        //2.Nonce distribution
        sendNonce();
        //3. Signature computing and sending
        computeAndSendSignature();


    }
    static void computeAndSendSignature(){
        String messageA=adam.computeSignature();
        String messageB=bobek.computeSignature();

    }
    static void sendNonce(){
        adam.setR();
        bobek.setR();

        String messageA =adam.getUserID()+"0"+adam.getR();
        String messageB=bobek.getUserID()+"0"+bobek.getR();

        adam.addNonce(messageB);
        bobek.addNonce(messageA);



    }

   static public void RSADistribution() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        KeyPair keyPair2=keyPairGenerator.genKeyPair();

         adam= new User();
         bobek= new User();
       adam.getPossibleUsers().add(adam.getUserID());
       adam.getPossibleUsers().add(bobek.getUserID());
       bobek.getPossibleUsers().add(adam.getUserID());
       bobek.getPossibleUsers().add(bobek.getUserID());

       //Powinno być bezpiecznym kanałem np przez plik na dysku
        adam.setMyKey(keyPair.getPrivate());
       adam.getOtherUsersKey().put(bobek.getUserID(),keyPair2.getPublic());
        bobek.setMyKey(keyPair2.getPrivate());
        bobek.getOtherUsersKey().put(adam.getUserID(),keyPair.getPublic());



        // 2.Real algorithm
    }
}