import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;


public class SS7CryptoModule {

    private static final int NONCE_LENGTH = 12;
    private static final int KEY_LENGTH = 32;

    public static byte[] generateKey() {
        byte[] key = new byte[KEY_LENGTH];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static byte[] encrypt(byte[] message, byte[] key, byte[] nonce) throws GeneralSecurityException {
        if (key.length != KEY_LENGTH) throw new IllegalArgumentException("Invalid key length");
        if (nonce.length != NONCE_LENGTH) throw new IllegalArgumentException("Invalid nonce length");

        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher.doFinal(message);
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] nonce) throws GeneralSecurityException {
        if (key.length != KEY_LENGTH) throw new IllegalArgumentException("Invalid key length");
        if (nonce.length != NONCE_LENGTH) throw new IllegalArgumentException("Invalid nonce length");

        SecretKey secretKey = new SecretKeySpec(key, "ChaCha20");
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        try {
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw new SecurityException("Authentication failed: message may have been tampered with.", e);
        }
    }

    public static void main(String[] args) {
        try {
            String ss7Payload = "MAP: SRI-SM IMSI: 404200123456789 MSISDN: +919876543210 MSC: 404210789456123 MessageType: SRI-SM";
                                
            byte[] message = ss7Payload.getBytes(StandardCharsets.UTF_8);

            byte[] key = generateKey();
            byte[] nonce = generateNonce();

            byte[] encrypted = encrypt(message, key, nonce);
            byte[] decrypted = decrypt(encrypted, key, nonce);

            System.out.println("Original SS7 Message: " + ss7Payload);
            System.out.println("Encrypted Message (Base64): " + java.util.Base64.getEncoder().encodeToString(encrypted));
            System.out.println("Decrypted SS7 Message: " + new String(decrypted, StandardCharsets.UTF_8));

        } catch (IllegalArgumentException e) {
            System.err.println("[ERROR] Invalid input: " + e.getMessage());
        } catch (SecurityException e) {
            System.err.println("[SECURITY] Message integrity check failed: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            System.err.println("[CRYPTO ERROR] An error occurred during encryption/decryption: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("[FATAL] Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
