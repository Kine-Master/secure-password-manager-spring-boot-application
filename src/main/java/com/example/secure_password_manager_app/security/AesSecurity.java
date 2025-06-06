package com.example.secure_password_manager_app.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility class for AES encryption and decryption of password entries.
 * Uses a secret key and salt from application properties to secure sensitive data.
 */
@Component
public class AesSecurity {

    private static SecretKeySpec secretKeySpec; // Renamed from secretKey to avoid confusion with the String value
    private static byte[] keyBytes; // Renamed from key to be more descriptive

    // The secret key is injected from application.properties
    @Value("${encryption.secret-key}") // UPDATED: Changed property name from aes.secret.key
    private String SECRET_KEY_STRING;

    @Value("${encryption.salt}") // NEW: Salt for key derivation
    private String SALT_STRING;

    // This method is called by Spring after dependency injection to initialize the key
    @jakarta.annotation.PostConstruct
    public void init() {
        setKey(SECRET_KEY_STRING, SALT_STRING);
    }

    private static void setKey(String mySecretKey, String salt) {
        MessageDigest sha = null;
        try {
            // Combine secret key and salt for stronger key derivation
            keyBytes = (mySecretKey + salt).getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-1"); // Still using SHA-1 as per previous logic
            keyBytes = sha.digest(keyBytes);
            keyBytes = Arrays.copyOf(keyBytes, 16); // Use only first 16 bytes for AES-128
            secretKeySpec = new SecretKeySpec(keyBytes, "AES"); // UPDATED: Renamed variable
        } catch (Exception e) {
            System.out.println("Error setting AES key: " + e.toString());
        }
    }

    public String encrypt(String strToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec); // UPDATED: Renamed variable
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public String decrypt(String strToDecrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec); // UPDATED: Renamed variable
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
}