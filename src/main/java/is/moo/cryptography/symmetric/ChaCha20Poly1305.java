package is.moo.cryptography.symmetric;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ChaCha20Poly1305 {

    /**
     * JEP 329: ChaCha20 and Poly1305 Cryptographic Algorithms
     */
    private static final String CHACHA20 = "ChaCha20";
    private static final String CRYPTOGRAPHIC_ALGORITHM = "ChaCha20-Poly1305";
    /**
     * The TLS ChaCha20 as defined in RFC7539
     */
    private static final int NONCE_LENGTH = 12;
    private static final int MAC_LENGTH = 16;

    /**
     * Key Length
     * - Key length for ChaCha20 must be 256 bits
     */
    private static final int KEY_POWER = 256;

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CHACHA20);
        keyGenerator.init(KEY_POWER, SecureRandom.getInstanceStrong());
        return keyGenerator.generateKey();
    }

    public static String encrypt(String text, String key) throws Exception {
        Cipher cipher = Cipher.getInstance(CRYPTOGRAPHIC_ALGORITHM);
        byte[] nonce = getNonce();

        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), CHACHA20);
        IvParameterSpec iv = new IvParameterSpec(nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        byte[] encryptedText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

        return Hex.encodeHexString(ByteBuffer
                .allocate(encryptedText.length + NONCE_LENGTH)
                .put(encryptedText)
                .put(nonce)
                .array());
    }

    public static String decrypt(String text, String key) throws Exception {
        byte[] decodedText = Hex.decodeHex(text);
        ByteBuffer bb = ByteBuffer.wrap(decodedText);
        byte[] encryptedText = new byte[decodedText.length - NONCE_LENGTH];
        byte[] nonce = new byte[NONCE_LENGTH];
        bb.get(encryptedText);
        bb.get(nonce);

        Cipher cipher = Cipher.getInstance(CRYPTOGRAPHIC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), CHACHA20);
        IvParameterSpec iv = new IvParameterSpec(nonce);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

        byte[] output = cipher.doFinal(encryptedText);
        return new String(output, StandardCharsets.UTF_8);

    }

    private static byte[] getNonce() {
        byte[] newNonce = new byte[12];
        new SecureRandom().nextBytes(newNonce);
        return newNonce;
    }

    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }

    public static void main(String[] args) throws Exception {
        String key = "DEUNGSIMANSIMCHADOLARONGSATE@EAT";
        String plainString = "Moomoo~ Says moo!";
        String enc = ChaCha20Poly1305.encrypt(plainString, key);
        System.out.println(enc);
        String dec = ChaCha20Poly1305.decrypt(enc, key);
        System.out.println(dec);
    }
}
