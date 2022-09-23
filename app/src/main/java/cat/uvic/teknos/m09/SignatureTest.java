package cat.uvic.teknos.m09;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;

public class SignatureTest {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        byte[] messageBytes = Files.readAllBytes(Paths.get("app/src/main/resources/message.txt"));

        var md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(messageBytes);

        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("app/src/main/resources/m09.p12"), "Teknos01.".toCharArray());
        var privateKey =
                (PrivateKey) keyStore.getKey("sele_signed_ca", "Teknos01.".toCharArray());

        var certificate = keyStore.getCertificate("sele_signed_ca");
        var publicKey = certificate.getPublicKey();

        var cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] digitalSignature = cipher.doFinal(messageHash);


        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedMessageHash = cipher.doFinal(digitalSignature);

    }
}
