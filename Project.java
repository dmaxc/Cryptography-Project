import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Project {
    public static void main(String[] args) {
        String secretKey = "Cryptography";
        String salt = "CS4600";

        try {
            // Read the plaintext message from SecretMessage.txt
            String message = Files.readString(Paths.get("SecretMessage.txt")).trim();

            System.out.println("Encrypting the message from SecretMessage.txt...");

            // Generate RSA keys and encrypt key and salt
            RSA.generateRSAKeyPair("RSAKey");
            PublicKey publicKey = RSA.loadPublicKey("RSAKey_public.key");

            byte[] encryptedKey = RSA.encrypt(secretKey, publicKey);
            byte[] encryptedSalt = RSA.encrypt(salt, publicKey);

            String encryptedKeyStr = Base64.getEncoder().encodeToString(encryptedKey);
            String encryptedSaltStr = Base64.getEncoder().encodeToString(encryptedSalt);

            // AES Encryption
            String encryptedMessage = AESEncryption.encrypt(message, secretKey, salt);

            // Generate MAC
            String mac = MAC.macString(encryptedMessage, secretKey);

            // Write encrypted data and MAC to files
            Files.write(Paths.get("EncryptedMessage.txt"), encryptedMessage.getBytes());
            Files.write(Paths.get("EncryptedKey.txt"), encryptedKeyStr.getBytes());
            Files.write(Paths.get("EncryptedSalt.txt"), encryptedSaltStr.getBytes());
            Files.write(Paths.get("MAC.txt"), mac.getBytes());

            System.out.println("Encryption complete. Files generated:");
            System.out.println("- EncryptedMessage.txt");
            System.out.println("- EncryptedKey.txt");
            System.out.println("- EncryptedSalt.txt");
            System.out.println("- MAC.txt");

            System.out.println("\nDecrypting the message...");

            // Load RSA private key
            PrivateKey privateKey = RSA.loadPrivateKey("RSAKey_private.key");

            // Read the encrypted files
            String encryptedMessageRead = Files.readString(Paths.get("EncryptedMessage.txt")).trim();
            String encryptedKeyStrRead = Files.readString(Paths.get("EncryptedKey.txt")).trim();
            String encryptedSaltStrRead = Files.readString(Paths.get("EncryptedSalt.txt")).trim();
            String originalMac = Files.readString(Paths.get("MAC.txt")).trim();

            // Decrypt key and salt using RSA
            String decryptedKey = RSA.decrypt(Base64.getDecoder().decode(encryptedKeyStrRead), privateKey);
            String decryptedSalt = RSA.decrypt(Base64.getDecoder().decode(encryptedSaltStrRead), privateKey);

            // Decrypt the message using AES
            String decryptedMessage = AESDecryption.decrypt(encryptedMessageRead, decryptedKey, decryptedSalt);

            // Verify MAC
            String generatedMac = MAC.macString(encryptedMessageRead, decryptedKey);

            // Show decrypted message and MAC comparison
            System.out.println("Decrypted message: " + decryptedMessage);

            System.out.println("\nMAC Comparison:");
            System.out.println("Original MAC (from file): " + originalMac);
            System.out.println("Generated MAC (calculated): " + generatedMac);

            if (originalMac.equals(generatedMac)) {
                System.out.println("MAC verification succeeded.");
            } else {
                System.out.println("MAC verification failed.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
