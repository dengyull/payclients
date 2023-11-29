package payment.liangdengyu.payclients;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class RSAUtil {


    private static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] wrapKey(Key keyToWrap, PublicKey wrappingKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.WRAP_MODE, wrappingKey);
        return cipher.wrap(keyToWrap);
    }

    public static Key unwrapKey(byte[] wrappedKeyData, String wrappedKeyAlgorithm, PrivateKey unwrappingKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.UNWRAP_MODE, unwrappingKey);
        return cipher.unwrap(wrappedKeyData, wrappedKeyAlgorithm, Cipher.SECRET_KEY);
    }
}
