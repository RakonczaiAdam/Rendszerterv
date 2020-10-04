package hu.radamka.rendszerterv;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;


class RSA{

    private PublicKey pubRsa;
    private PrivateKey privRsa;

    public RSA() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        pubRsa = kp.getPublic();
        privRsa = kp.getPrivate();
        System.out.println("Bob létrehozza az RSA kulcsokat\nPublikus kulcs: "+Base64.encode(pubRsa.getEncoded())+"\nPrivát kulcs: "+Base64.encode(privRsa.getEncoded())+"\n");
    }

    public String rsaEncrypt(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubRsa);
        return Base64.encode(cipher.doFinal(secretKey.getEncoded()));
    }

    public byte[] rsaDencrypt(String encryptedSecret) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privRsa);
        return cipher.doFinal(Base64.decode(encryptedSecret));
    }

}

class Symmetric{

    private SecretKey secretKey;

    public Symmetric() throws NoSuchAlgorithmException {
        KeyGenerator keyGen =  KeyGenerator.getInstance("AES");
        keyGen.init(256);
        secretKey = keyGen.generateKey();
        System.out.println("Alice létrehozza a szimmetrikus kulcsot\n"+ Base64.encode(secretKey.getEncoded())+"\n");
    }

    public byte[] symmetricEncrypt(String msg) throws NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec k = new SecretKeySpec(secretKey.getEncoded(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, k);
        return cipher.doFinal(msg.getBytes("UTF-8"));
    }

    public String symmetricDecrypt(byte[] encryptedMsg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec k = new SecretKeySpec(secretKey.getEncoded(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, k);
        return new String(cipher.doFinal(encryptedMsg));
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }
}

public class Main {

    public static void main(String[] args) {
        try {
            RSA rsa = new RSA();
            Symmetric symmetric = new Symmetric();
            String encryptedKey = rsa.rsaEncrypt(symmetric.getSecretKey());
            System.out.println("Alice titkosítja a szimmetrikus kulcsot Bob publikus kulcsával:\n"+ encryptedKey+"\n");
            byte[] key = rsa.rsaDencrypt(encryptedKey);
            System.out.println("Bob dekódolja a szimmetrikus kulcsot a privát kulcsával: \n"+Base64.encode(key)+"\n");
            byte[] encryptedMsg = symmetric.symmetricEncrypt("Hello!");
            System.out.println("Bob titkosítja az üzenetét a szimmetrikus kulccsal: \n"+ Base64.encode(encryptedMsg)+"\n");
            String message = symmetric.symmetricDecrypt(encryptedMsg);
            System.out.println("Alice dekódolja az üzenetet a szimmetrikus kulccsal: \n"+ message+"\n");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

}
