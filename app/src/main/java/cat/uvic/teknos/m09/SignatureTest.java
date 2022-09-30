package cat.uvic.teknos.m09;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SignatureTest {
    public static void main(String[] args) throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException {
        var message = Files.readAllBytes(Paths.get("app/src/main/resources/message.txt"));

        var keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("app/src/main/resources/m09.p12"), "Teknos01.".toCharArray());
        var privateKey = keystore.getKey("self_signed_ca", "Teknos01.".toCharArray());

        var signer = Signature.getInstance("SHA256withRSA");
        signer.initSign((PrivateKey) privateKey);
        signer.update(message);

        var signature = signer.sign();

        var base64Encoder = Base64.getEncoder();
        var cipherTextBase64 = base64Encoder.encodeToString(signature);

        System.out.println("Signature: " +  base64Encoder.encodeToString(signature));

        // verify
        var certificateFactory = CertificateFactory.getInstance("X.509");
        var certificate = certificateFactory.generateCertificate(new FileInputStream("app/src/main/resources/certificate.cer"));
        try {
            ((X509Certificate) certificate).checkValidity();
        } catch( Exception e) {
            System.out.println(e.getMessage());
        }
        var publicKey = certificate.getPublicKey();

        signer.initVerify(publicKey);
        signer.update(message);

        var isValid = signer.verify(signature);

        System.out.println("Signature is valid: " + isValid);

    }
}
