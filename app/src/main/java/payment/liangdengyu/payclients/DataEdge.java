package payment.liangdengyu.payclients;

import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKyberKeyFromResource;

import android.content.Context;
import android.os.SystemClock;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import payment.liangdengyu.payclients.kyber.KyberKEMExtractor;
import payment.liangdengyu.payclients.kyber.KyberKEMGenerator;
import payment.liangdengyu.payclients.kyber.KyberKeyGenerationParameters;
import payment.liangdengyu.payclients.kyber.KyberKeyPairGenerator;
import payment.liangdengyu.payclients.kyber.KyberParameters;
import payment.liangdengyu.payclients.kyber.KyberPrivateKeyParameters;
import payment.liangdengyu.payclients.kyber.KyberPublicKeyParameters;

public class DataEdge {
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static AsymmetricCipherKeyPair kyberkeyPair;


    public static String aesDecrypt(String base64EncryptedData, String base64Iv, byte[] aesKeyBytes) throws Exception {
        // Decode the base64 encoded string
        SecretKey aesKey = convertBytesToSecretKey(aesKeyBytes);
        byte[] encryptedData = Base64.decode(base64EncryptedData, Base64.NO_WRAP);
        byte[] iv = Base64.decode(base64Iv, Base64.NO_WRAP);

        // Rebuild key using SecretKeySpec if necessary
        SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getEncoded(), "AES");

        // Initialize the cipher for decryption
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        // Perform decryption
        byte[] decryptedData = aesCipher.doFinal(encryptedData);

        return new String(decryptedData, StandardCharsets.UTF_8);
    }
    public static SecretKey convertBytesToSecretKey(byte[] aesKeyBytes) {
        return new SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
    }

    public static byte[] encryptWithAES(String plaintext, byte[] sharedSecretKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec aesKey = new SecretKeySpec(sharedSecretKey, "AES");

        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return aesCipher.doFinal(plaintext.getBytes());
    }

    public static String decryptWithAES(byte[] ciphertext, byte[] sharedSecretKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec aesKey = new SecretKeySpec(sharedSecretKey, "AES");

        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedBytes = aesCipher.doFinal(ciphertext);

        return new String(decryptedBytes);
    }
    public static String decryptWithAES(String ciphertext, String sharedSecretKey) throws Exception {


        return decryptWithAES(Base64.decode(ciphertext, Base64.NO_WRAP),Base64.decode(sharedSecretKey, Base64.NO_WRAP));
    }

    public static String[] aesEncryKyber(String dataToEncrypt, Context context) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        SecretKey aesKey = keyGen.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedData = aesCipher.doFinal(dataToEncrypt.getBytes(StandardCharsets.UTF_8));
        String[] res= new String[5];
        String base64EncryptedData = Base64.encodeToString(encryptedData, Base64.NO_WRAP);
        res[0] = Base64.encodeToString(encryptedData, Base64.NO_WRAP);


        byte[] iv = aesCipher.getIV();
        String base64Iv = Base64.encodeToString(iv, Base64.NO_WRAP);
        res[1] = Base64.encodeToString(iv, Base64.NO_WRAP);

        KyberPublicKeyParameters KyberPublicKey = KeyPairUtils.readKyberPublicKeyFromFile(context);
        KyberPrivateKeyParameters KyberPrivateKey = KeyPairUtils.readKyberPrivateKeyFromFile(context);

        KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.init(new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber1024));
        kyberkeyPair = new AsymmetricCipherKeyPair(KyberPublicKey, KyberPrivateKey);//keyPairGenerator.generateKeyPair();
        // Generate the shared secret and the encapsulation
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(new SecureRandom());
        SecretWithEncapsulation secEnc = kemGenerator.generateEncapsulated(KeyPairUtils.readKyberPublicKeyFromFile(context));
        //SecretWithEncapsulation secEnc = kemGenerator.generateEncapsulated(kyberkeyPair.getPublic());
        byte[] sharedSecret = secEnc.getSecret();
        byte[] aesKeyBytes = aesKey.getEncoded();

        // Use the shared secret to encrypt the AES key
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedAesKey = cipher.doFinal(aesKeyBytes);
        String base64EncryptedAesKey = Base64.encodeToString(encryptedAesKey, Base64.NO_WRAP);
        res[2] = base64EncryptedAesKey;
        byte[] ivs = cipher.getIV();

        // Extract the shared secret
        KyberKEMExtractor kemExtractor = new KyberKEMExtractor( KeyPairUtils.readKyberPrivateKeyFromFile(context));
        //KyberKEMExtractor kemExtractor = new KyberKEMExtractor((KyberPrivateKeyParameters) kyberkeyPair.getPrivate());
        byte[] decapsulatedSecret = kemExtractor.extractSecret(secEnc.getEncapsulation());
        res[3] = Base64.encodeToString(secEnc.getEncapsulation(), Base64.NO_WRAP);
        // Decrypt the AES key
        Cipher ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpecs = new SecretKeySpec(decapsulatedSecret, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivs);
        ecipher.init(Cipher.DECRYPT_MODE, secretKeySpecs, ivSpec);
        byte[] decryptedAesKeyBytes = ecipher.doFinal(encryptedAesKey);
        String base64decryptedAesKeyBytes = Base64.encodeToString(decryptedAesKeyBytes, Base64.NO_WRAP);

        res[4] = Base64.encodeToString(ivs, Base64.NO_WRAP);


        return res;
    }

    public static byte[] aesDecryKyber(String base64EncryptedData, String base64Ivs, String base64EncryptedAesKey, KyberPrivateKeyParameters kyberPrivateKey) throws Exception {

        byte[] encryptedData = Base64.decode(base64EncryptedData, Base64.NO_WRAP);
        byte[] iv = Base64.decode(base64Ivs, Base64.NO_WRAP);
        byte[] encryptedAesKey = Base64.decode(base64EncryptedAesKey, Base64.NO_WRAP);
        // Extract the shared secret
        KyberKEMExtractor kemExtractor = new KyberKEMExtractor(kyberPrivateKey);
        byte[] decapsulatedSecret = kemExtractor.extractSecret(encryptedAesKey);


        // Decrypt the AES key
        Cipher ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpecs = new SecretKeySpec(decapsulatedSecret, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        ecipher.init(Cipher.DECRYPT_MODE, secretKeySpecs, ivSpec);
        byte[] decryptedAesKeyBytes = ecipher.doFinal(encryptedData);
        String base64decryptedAesKeyBytes = Base64.encodeToString(decryptedAesKeyBytes, Base64.NO_WRAP);
        return decryptedAesKeyBytes;
    }
    public static String[] aesEncry(String dataToEncrypt, Context context) throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        SecretKey aesKey = keyGen.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedData = aesCipher.doFinal(dataToEncrypt.getBytes(StandardCharsets.UTF_8));
        String[] res= new String[4];
        String base64EncryptedData = Base64.encodeToString(encryptedData, Base64.NO_WRAP);
        res[0] = Base64.encodeToString(encryptedData, Base64.NO_WRAP);


        byte[] iv = aesCipher.getIV();
        String base64Iv = Base64.encodeToString(iv, Base64.NO_WRAP);
        res[1] = Base64.encodeToString(iv, Base64.NO_WRAP);


        PublicKey rsaPublicKey = KeyPairUtils.readPublicKeyFromResource(context);// ... obtain recipient's RSA public key

        Cipher rsaCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        rsaCipher.init(Cipher.WRAP_MODE, rsaPublicKey);
        byte[] encryptedAesKey = rsaCipher.wrap(aesKey);
        String base64EncryptedAesKey = Base64.encodeToString(encryptedAesKey, Base64.NO_WRAP);
        byte[] encryptedAesKeys  = Base64.decode(base64EncryptedAesKey, Base64.NO_WRAP);
        res[2] = base64EncryptedAesKey;
        res[3] = Base64.encodeToString(aesKey.getEncoded(), Base64.NO_WRAP);

//        Log.d("HTTP Response", aesDecry(res[0], res[2], res[1], context));
        return res;
    }

    public String encrypt(String input, String encryptedKey, String iv,Context context) throws Exception {
        byte[] aesKeyBytes = Base64.decode(encryptedKey.trim(),Base64.NO_WRAP);
        PrivateKey rsaPrivateKey = KeyPairUtils.readPrivateKeyFromResource(context); // Assuming this method is defined to read the private key
        SecretKey originalKey = (SecretKey) RSAUtil.unwrapKey(aesKeyBytes, "AES", rsaPrivateKey);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.decode(iv,Base64.NO_WRAP));
        return encrypt(input,originalKey,ivParameterSpec);
    }
    // Encrypt a string with AES
    public String encrypt(String input, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.encodeToString(cipherText,Base64.NO_WRAP);
    }
    public String decrypt(String cipherText, String encryptedKey, String iv,Context context) throws Exception {
        byte[] aesKeyBytes = Base64.decode(encryptedKey.trim(),Base64.NO_WRAP);
        PrivateKey rsaPrivateKey = KeyPairUtils.readPrivateKeyFromResource(context); // Assuming this method is defined to read the private key

        SecretKey originalKey = (SecretKey) RSAUtil.unwrapKey(aesKeyBytes, "AES", rsaPrivateKey);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.decode(iv,Base64.NO_WRAP));
        return decrypt(cipherText,originalKey,ivParameterSpec);
    }

    // Decrypt a string with AES
    public String decrypt(String cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.decode(cipherText,Base64.NO_WRAP));
        return new String(plainText);
    }
    private static final String AES = "AES";
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    public static String aesDecry(String base64EncryptedData, String base64EncryptedAesKey, String base64Iv, Context context) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidAlgorithmParameterException {
        // Decode the base64 encoded data
        byte[] encryptedData = Base64.decode(base64EncryptedData, Base64.NO_WRAP);
        byte[] encryptedAesKey = Base64.decode(base64EncryptedAesKey, Base64.NO_WRAP);
        byte[] iv = Base64.decode(base64Iv, Base64.NO_WRAP);

        // Decrypt the AES key with RSA private key
        PrivateKey rsaPrivateKey = KeyPairUtils.readPrivateKeyFromResource(context); // Assuming this method is defined to read the private key
        Cipher rsaCipher = Cipher.getInstance(CIPHER_ALGORITHM);
        rsaCipher.init(Cipher.UNWRAP_MODE, rsaPrivateKey);
        SecretKey aesKey = (SecretKey) rsaCipher.unwrap(encryptedAesKey, "AES", Cipher.SECRET_KEY);

        // Set up AES Cipher in decryption mode
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);

        // Decrypt the data
        byte[] decryptedData = aesCipher.doFinal(encryptedData);

        // Convert decrypted bytes to String and return
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    public static PublicKey readPublicKeyFromFile(Context context) {
        try {
            InputStream is = context.getResources().openRawResource(R.raw.publickey);
            byte[] keyBytes = new byte[is.available()];
            is.read(keyBytes);
            is.close();

            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            // Handle exceptions
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey readPrivateKeyFromFile(Context context) {
        try {
            InputStream is = context.getResources().openRawResource(R.raw.privatekey);
            byte[] keyBytes = new byte[is.available()];
            is.read(keyBytes);
            is.close();

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            // Handle exceptions
            e.printStackTrace();
        }
        return null;
    }

    public static KyberPublicKeyParameters readKyberPublicKeyFromFile(Context context) {
        try {
            InputStream is = context.getResources().openRawResource(R.raw.publickey);
            byte[] keyBytes = new byte[is.available()];
            is.read(keyBytes);
            is.close();

            KyberParameters parameters = KyberParameters.kyber1024;
            return new KyberPublicKeyParameters(parameters, keyBytes);
        } catch (IOException e) {
            // Handle exceptions
            e.printStackTrace();
        }
        return null;
    }

    public static KyberPrivateKeyParameters readKyberPrivateKeyFromFile(Context context) {
        try {
            InputStream is = context.getResources().openRawResource(R.raw.privatekey);
            byte[] keyBytes = new byte[is.available()];
            is.read(keyBytes);
            is.close();

            KyberParameters parameters = KyberParameters.kyber1024;
            return new KyberPrivateKeyParameters(parameters, keyBytes);
        } catch (IOException e) {
            // Handle exceptions
            e.printStackTrace();
        }
        return null;
    }

    public static String RSAsignData(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] digitalSignature = signature.sign();
        return Base64.encodeToString(digitalSignature, Base64.NO_WRAP);
    }
    public static String FalconsignData(String data, PrivateKey privKey) throws Exception{
        return FalconsignData(data.getBytes(StandardCharsets.UTF_8),privKey);
    }
    public static String FalconsignData(byte[] data, PrivateKey privKey) throws Exception {
        Signature signature = Signature.getInstance("FALCON-1024", "BCPQC");
        signature.initSign(privKey);
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        return Base64.encodeToString(digitalSignature, Base64.NO_WRAP);
    }
    public static boolean FalconverifySignature(byte[] data, byte[] signatureBytes, PublicKey pubKey) throws Exception {
        Signature signature = Signature.getInstance("FALCON-1024", "BCPQC");
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }
    public static KeyPair FalconKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("FALCON-1024", "BCPQC");
        KeyPair keyPair = keyGen.generateKeyPair();
        return keyPair;
    }
    public static String DilithiumsignData(String data, PrivateKey privKey) throws Exception{
        return DilithiumsignData(data.getBytes(StandardCharsets.UTF_8),privKey);
    }
    public static String DilithiumsignData(byte[] data, PrivateKey privKey) throws Exception {
        Signature signature = Signature.getInstance("Dilithium", "BCPQC");
        signature.initSign(privKey);
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        return Base64.encodeToString(digitalSignature, Base64.NO_WRAP);
    }
    public static KeyPair DilithiumKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Dilithium5", "BCPQC");
        KeyPair keyPaird = keyGen.generateKeyPair();
        return keyPaird;
    }
    public static SecretKey aesGenerateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        SecretKey aesKey = keyGen.generateKey();
        return aesKey;
    }
    public static boolean DILITHIUMSignVertify(PublicKey publicKey, byte[] decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        Signature signature = Signature.getInstance("Dilithium","BCPQC");
        signature.initVerify(publicKey);
        signature.update(decryptedData);
        byte[] decodedSignature = Base64.decode(digitalsign,Base64.NO_WRAP);
        return signature.verify(decodedSignature);
    }

    public static X509Certificate convertFromPEM(String pemString) throws Exception {
        // Remove the first and last lines (PEM headers and footers)
        String base64Encoded = pemString.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", ""); // Remove all whitespace

        // Decode the Base64 encoded bytes
        byte[] certificateBytes = Base64.decode(base64Encoded,Base64.NO_WRAP);

        // Create a CertificateFactory
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Generate X509Certificate
        X509Certificate certificate = (X509Certificate) certificateFactory
                .generateCertificate(new ByteArrayInputStream(certificateBytes));

        return certificate;
    }
    public static boolean verifyCertificate(X509Certificate cert, PublicKey caPublicKey) {
        try {
            cert.checkValidity(); // Checks whether the certificate is currently valid
            cert.verify(caPublicKey); // Verifies the certificate's signature with the CA's public key
            System.out.println("Certificate is valid.");
            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            System.out.println("Certificate is not valid: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("Error during certificate verification: " + e.getMessage());
            return false;
        }
    }

    public static byte[] createDigest(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-384");
        byte[] hash = digest.digest(data);
        return hash;
    }
    public static String RSAsignData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] digitalSignature = signature.sign();
        return Base64.encodeToString(digitalSignature, Base64.NO_WRAP);
    }
    public static JsonObject rsaJsonEncry(String data, Context context) throws Exception {
        long startTime = System.nanoTime();
        JsonObject sentjson = new JsonObject();

        aesKey = DataEdge.aesGenerateKey();//
        String encodedKey = java.util.Base64.getEncoder().encodeToString(aesKey.getEncoded());
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] iv = aesCipher.getIV();//
        byte[] encryptedData = aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));//
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.WRAP_MODE, KeyPairUtils.readPublicKeyFromResource(context));
        byte[] encryptedAesKey = rsaCipher.wrap(aesKey);
        String base64EncryptedData = java.util.Base64.getEncoder().encodeToString(encryptedData);
        String base64Iv = java.util.Base64.getEncoder().encodeToString(iv);
        piv = base64Iv;
        String base64EncryptedAesKey = java.util.Base64.getEncoder().encodeToString(encryptedAesKey);

        long cpuTimeBefore = System.nanoTime();
        byte[] Digest = DataEdge.createDigest(data.getBytes(StandardCharsets.UTF_8));
        String signiture = DataEdge.RSAsignData(Digest, KeyPairUtils.readPrivateKeyFromFile(context));
        long cpuTimeAfter = System.nanoTime();
        long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
//        Log.d("HTTP Response", "rsa Sign CPU time: "+(cpuCost/ 1_000_000)+"ms("+cpuCost+"ns)");

        sentjson.addProperty("encryptedData", base64EncryptedData);
        sentjson.addProperty("iv", base64Iv);
        sentjson.addProperty("encryptedKey", base64EncryptedAesKey);
        sentjson.addProperty("sign", signiture);
        sentjson.addProperty("publicKey", java.util.Base64.getEncoder().encodeToString(KeyPairUtils.readPublicKeyFromFile(context).getEncoded()));
//        long endTime = System.nanoTime();
//        long elapsedTime = endTime - startTime;
//        Log.d("HTTP Response", "Elapsed CPU time: " + (elapsedTime/ 1_000_000) +"ms("+elapsedTime+"ns)");
        long vertimes = System.nanoTime();
//        if(RsaSignVertify(KeyPairUtils.readPublicKeyFromFile(context), Digest, signiture)){
//            Log.d("HTTP Response", "success Rsa");
//            long cpuTimeAfters = System.nanoTime();
//            long cpuCosts = cpuTimeAfters - vertimes; // In nanoseconds
//            Log.d("HTTP Response", "Rsa vertify Sign CPU time: "+(cpuCosts/ 1_000_000) +"ms("+cpuCosts+"ns)");
//        }
//        Log.d("HTTP Response", String.valueOf(signiture.length()));
//        Log.d("HTTP Response", String.valueOf(base64EncryptedAesKey.length()));
//        Log.d("HTTP Response", String.valueOf(java.util.Base64.getEncoder().encodeToString(KeyPairUtils.readPublicKeyFromFile(context).getEncoded()).length()));
//        Log.d("HTTP Response", String.valueOf(sentjson.toString().length()));
        long currentTimeMillis = System.currentTimeMillis();
        sentjson.addProperty("timestamp", currentTimeMillis);
        return sentjson;
    }
    public static JsonObject kyberJsonEncry(String data, Context context) throws Exception {
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        JsonObject sentjson = new JsonObject();
        long startTime = System.nanoTime();

        PublicKey publicKey = readPublicKyberKeyFromResource(context);
        SecretKeyWithEncapsulation secretKeyWithEncapsulationSender = PqcChrystalsKyberKem.pqcGenerateChrystalsKyberEncryptionKey(publicKey);
        byte[] encryptedSessionKey = secretKeyWithEncapsulationSender.getEncapsulation();
        Cipher aesCiphers = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesKey = new SecretKeySpec(secretKeyWithEncapsulationSender.getEncoded(), "AES");
        aesCiphers.init(Cipher.ENCRYPT_MODE, aesKey);
        String encodedKeys = java.util.Base64.getEncoder().encodeToString(aesKey.getEncoded());
        byte[] encryptedDatas = aesCiphers.doFinal(data.getBytes(StandardCharsets.UTF_8));
        byte[] ivs = aesCiphers.getIV();//

        String base64EncryptedDatas = java.util.Base64.getEncoder().encodeToString(encryptedDatas);
        String base64Ivs = java.util.Base64.getEncoder().encodeToString(ivs);
        piv = base64Ivs;
        String base64encryptedSessionKeys = java.util.Base64.getEncoder().encodeToString(encryptedSessionKey);

        long cpuTimeBefore = System.nanoTime();
        byte[] Digests = DataEdge.createDigest(data.getBytes(StandardCharsets.UTF_8));
        String signitures = "";
        String change = PreferenceUtil.getSavedSwitchSign(context);
        PublicKey signpublic = null;
        PrivateKey signprivate;
        switch(change){
            case "Dilithium":
                signpublic = KeyPairUtils.readObjectFromFile(context, KeyPairUtils.DilithiumPUBLIC_KEY_FILE);
                signprivate = KeyPairUtils.readObjectFromFile(context, KeyPairUtils.DilithiumPRIVATE_KEY_FILE);
                signitures = DilithiumsignData(Digests,signprivate);
//                long vertime = System.nanoTime();
//                if(DILITHIUMSignVertify(signpublic, Digests, signitures)){
//                    long cpuTimeAfter = System.nanoTime();
//                    long cpuCost = cpuTimeAfter - vertime; // In nanoseconds
//                    Log.d("HTTP Response", change+" Sign CPU time: "+(cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
//                    Log.d("HTTP Response", "success DILITHIUMSignVertify");
//                }

                break;
            case "Falcon":
                KeyFactory keyFactoryFALCON = KeyFactory.getInstance("FALCON-1024", "BCPQC");
                signpublic = keyFactoryFALCON.generatePublic(new X509EncodedKeySpec(KeyPairUtils.readObjectFromFile(context, KeyPairUtils.FalconPUBLIC_KEY_FILE)));
                signprivate = keyFactoryFALCON.generatePrivate(new PKCS8EncodedKeySpec(KeyPairUtils.readObjectFromFile(context, KeyPairUtils.FalconPRIVATE_KEY_FILE)));
                signitures = FalconsignData(Digests,signprivate);
//                long vertimes = System.nanoTime();
//                if(FalconSignVertify(signpublic, Digests, signitures)){
//                    Log.d("HTTP Response", "success FalconSignVertify");
//                    long cpuTimeAfter = System.nanoTime();
//                    long cpuCost = cpuTimeAfter - vertimes; // In nanoseconds
//                    Log.d("HTTP Response", change+" vertify CPU time: "+(cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
//                }
        }
//        long cpuTimeAfter = System.nanoTime();
//        long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
//        Log.d("HTTP Response", change+" Sign CPU time: "+(cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
        sentjson.addProperty("encryptedData", base64EncryptedDatas);
        sentjson.addProperty("iv", base64Ivs);
        sentjson.addProperty("encryptedKey", base64encryptedSessionKeys);
        sentjson.addProperty("sign", signitures);
        sentjson.addProperty("publicKey", Base64.encodeToString(signpublic.getEncoded(), Base64.NO_WRAP));
        sentjson.addProperty("signmethod", change);
//        long endTime = System.nanoTime();
//        long elapsedTime = endTime - startTime;
//        Log.d("HTTP Response", "Elapsed CPU time: " + (elapsedTime/ 1_000_000) +"ms("+elapsedTime+"ns)");
//        Log.d("HTTP Response", String.valueOf(signitures.length()));
//        Log.d("HTTP Response", String.valueOf(base64encryptedSessionKeys.length()));
//        Log.d("HTTP Response", String.valueOf(Base64.encodeToString(signpublic.getEncoded(), Base64.NO_WRAP).length()));
//        Log.d("HTTP Response", String.valueOf(sentjson.toString().length()));
        long currentTimeMillis = System.currentTimeMillis();
        sentjson.addProperty("timestamp", currentTimeMillis);
        return sentjson;
    }
    private static SecretKey aesKey;
    private static String piv;
    public static byte[] aesdecrypted(String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.decode(piv,Base64.NO_WRAP));
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
        byte[] plainText = cipher.doFinal(Base64.decode(cipherText,Base64.NO_WRAP));
        return plainText;
    }
    public static boolean FalconSignVertify(PublicKey publicKey, byte[] decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        Signature signature = Signature.getInstance("FALCON-1024", "BCPQC");
        signature.initVerify(publicKey);
        signature.update(decryptedData);
        byte[] decodedSignature = Base64.decode(digitalsign,Base64.NO_WRAP);
        return signature.verify(decodedSignature);
    }
    public static boolean FalconSignVertify(PublicKey publicKey, String decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {

        return FalconSignVertify(publicKey,Base64.decode(decryptedData,Base64.NO_WRAP), digitalsign);
    }
    public static boolean RsaSignVertify(PublicKey publicKey, byte[] decryptedData, String digitalsign) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {

        long id = Thread.currentThread().getId();
        long cpuTimeBefore = System.nanoTime();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(decryptedData);
        byte[] decodedSignature = Base64.decode(digitalsign,Base64.NO_WRAP);
        boolean result = signature.verify(decodedSignature);
        long cpuTimeAfterw = System.nanoTime();
        long cpuCost = cpuTimeAfterw - cpuTimeBefore; // In nanoseconds
        System.out.println("Rsa CPU Cost: "+ (cpuCost/ 1_000_000) +"ms("+cpuCost+"ns)");
        System.out.println("Rsa sign size: "+digitalsign.length());
        System.out.println("Rsa publicKey size: "+publicKey.getEncoded().length);
        return result;
    }
}
