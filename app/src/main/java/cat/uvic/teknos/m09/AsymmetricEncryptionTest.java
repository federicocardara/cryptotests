package cat.uvic.teknos.m09;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AsymmetricEncryptionTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var plainText = "Plain text ".repeat(3).getBytes();

        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        var keyPair = keyPairGenerator.generateKeyPair();

        System.out.println("Private key: " + keyPair.getPrivate());
        System.out.println("Public key: " + keyPair.getPublic());

        var cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        var cipherText = cipher.doFinal(plainText);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        var decryptedText = cipher.doFinal(cipherText);

        var base64Encoder = Base64.getEncoder();

        System.out.println("Plain text: " + new String(plainText));
        System.out.println("Cipher text: " + base64Encoder.encodeToString(cipherText));
        System.out.println("Decrypted text: " + new String(decryptedText));
    }
}
