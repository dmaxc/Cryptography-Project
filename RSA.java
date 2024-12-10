import javax.crypto.Cipher;
import java.io.IOException;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.security.*;
import java.security.spec.*;

public class RSA {

    public static void generateRSAKeyPair(String fileName) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        try (FileWriter pubWriter = new FileWriter(fileName + "_public.key");
             FileWriter privWriter = new FileWriter(fileName + "_private.key")) {

            pubWriter.write(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            privWriter.write(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        }
    }

    public static PublicKey loadPublicKey(String fileName) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(Files.readString(Paths.get(fileName)).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static PrivateKey loadPrivateKey(String fileName) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(Files.readString(Paths.get(fileName)).trim());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    public static byte[] encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    public static String decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(cipherText));
    }
}
