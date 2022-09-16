package cat.uvic.teknos.m09;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SymmetricEncryptionTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        var plaintText = "teknos".repeat(15);
        System.out.println("Plain text: " + plaintText);

        var keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        var secretKey = keyGenerator.generateKey();

        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");


        var secureRandom = new SecureRandom();
        var bytes = new byte[16];
        secureRandom.nextBytes(bytes);
        var iv = new IvParameterSpec(bytes);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        var cipherText = cipher.doFinal(plaintText.getBytes());

        var base64Encoder = Base64.getEncoder();
        var cipherTextBase64 = base64Encoder.encodeToString(cipherText);

        System.out.println("Encrypted text: " + cipherTextBase64);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        var decryptedTextBytes = cipher.doFinal(cipherText);
        var decryptedText = new String(decryptedTextBytes);

        System.out.println("Decrypted text: " + decryptedText);
    }
}
