package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class Main {
    static User adam, bobek;

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
        // 2.Nonce distribution
        sendNonce();
        //3. Signature computing and sending
        computeAndSendSignature();
        //4. X computing and send
        computeAndSendX();
        //5. get session Key
        establishSessionKey();


    }
    static void establishSessionKey(){
        adam.computeSessionKey();
        bobek.computeSessionKey();
       System.out.println("session:"+adam.sessionKey.equals(bobek.sessionKey));
    }

    static void computeAndSendX() {
        String messageA2 = adam.sendX();
        String messageB2 = bobek.sendX();
        bobek.reciveX(messageA2);
        adam.reciveX(messageA2);
        bobek.reciveX(messageB2);
        adam.reciveX(messageB2);

    }

    static void computeAndSendSignature() {
        String messageA = adam.computeSignature();
        String messageB = bobek.computeSignature();
        bobek.recieveSignature(messageA);
        adam.recieveSignature(messageA);
        bobek.recieveSignature(messageB);
        adam.recieveSignature(messageB);


    }

    static void sendNonce() {
        adam.setR();
        bobek.setR();

        String messageA = adam.getUserID() + "0" + adam.getR();
        String messageB = bobek.getUserID() + "0" + bobek.getR();

        adam.addNonce(messageB);
        bobek.addNonce(messageB);
        adam.addNonce(messageA);
        bobek.addNonce(messageA);


    }

    static public void RSADistribution() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        adam = new User();
        bobek = new User();
        adam.getPossibleUsers().add(adam.getUserID());
        adam.getPossibleUsers().add(bobek.getUserID());
        bobek.getPossibleUsers().add(adam.getUserID());
        bobek.getPossibleUsers().add(bobek.getUserID());

        //Powinno być bezpiecznym kanałem np przez plik na dysku
        adam.setPrivateKey(keyPair.getPrivate());
        adam.setPublicKey(keyPair.getPublic());
        bobek.setPrivateKey(keyPair.getPrivate());
        bobek.setPublicKey(keyPair.getPublic());


    }
}