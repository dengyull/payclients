package payment.liangdengyu.payclients;

import static payment.liangdengyu.payclients.PqcChrystalsKyberKem.getChrystalsKyberPublicKeyFromEncoded;

import android.content.Context;
import android.widget.Toast;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import payment.liangdengyu.payclients.kyber.KyberKeyGenerationParameters;
import payment.liangdengyu.payclients.kyber.KyberKeyPairGenerator;
import payment.liangdengyu.payclients.kyber.KyberParameters;
import payment.liangdengyu.payclients.kyber.KyberPrivateKeyParameters;
import payment.liangdengyu.payclients.kyber.KyberPublicKeyParameters;

public class KeyPairUtils {
    private static final String PRIVATE_KEY_FILE = "private_key.ser";
    private static final String PUBLIC_KEY_FILE = "public_key.ser";

    private static final String KYBER_PRIVATE_KEY_FILE = "kyber_private_key.ser";
    private static final String KYBER_PUBLIC_KEY_FILE = "kyber_public_key.ser";

    public static <T extends Serializable> T readObjectFromFile(Context context, String fileName) {
        try (FileInputStream fis = context.openFileInput(fileName);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (T) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Failed to read object from file: " + fileName, e);
        }
    }
    public static PublicKey readPublicKeyFromFile(Context context) {
        PublicKey publicKey = readObjectFromFile(context, PUBLIC_KEY_FILE);

        try (FileInputStream is = context.openFileInput(PUBLIC_KEY_FILE);
             ObjectInputStream ois = new ObjectInputStream(is)) {
            return (PublicKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Failed to read PublicKey from assets", e);
        }
    }

    public static PrivateKey readPrivateKeyFromFile(Context context) {
        PrivateKey privateKey = readObjectFromFile(context, PRIVATE_KEY_FILE);

        try (FileInputStream fis = context.openFileInput(PRIVATE_KEY_FILE);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return (PrivateKey) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Failed to read PrivateKey from internal storage", e);
        }
    }
    public static KyberPublicKeyParameters readKyberPublicKeyFromFile(Context context) {
        KyberPublicKeyParameters kyberPublicKey = new KyberPublicKeyParameters(KyberParameters.kyber1024,readObjectFromFile(context, KYBER_PUBLIC_KEY_FILE));

        try (FileInputStream is = context.openFileInput(KYBER_PUBLIC_KEY_FILE);
             ObjectInputStream ois = new ObjectInputStream(is)) {
            KyberParameters parameters = KyberParameters.kyber1024;
            return new KyberPublicKeyParameters(parameters, (byte[]) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Failed to read PublicKey from assets", e);
        }
    }

    public static KyberPrivateKeyParameters readKyberPrivateKeyFromFile(Context context) {
        KyberPrivateKeyParameters kyberPrivateKey = new KyberPrivateKeyParameters(KyberParameters.kyber1024,readObjectFromFile(context, KYBER_PUBLIC_KEY_FILE));

        try (FileInputStream fis = context.openFileInput(KYBER_PRIVATE_KEY_FILE);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            KyberParameters parameters = KyberParameters.kyber1024;
            return new KyberPrivateKeyParameters(parameters, (byte[]) ois.readObject());
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException("Failed to read PrivateKey from internal storage", e);
        }
    }

    public static PublicKey readPublicKeyFromResource(Context context) {
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
    public static PublicKey readPublicKyberKeyFromResource(Context context) {
        try {
            InputStream is = context.getResources().openRawResource(R.raw.kyberpublickey);
            byte[] keyBytes = new byte[is.available()];
            is.read(keyBytes);
            is.close();

            return getChrystalsKyberPublicKeyFromEncoded(keyBytes);
        } catch (IOException e) {
            // Handle exceptions
            e.printStackTrace();
        }
        return null;
    }
    public static PrivateKey readPrivateKeyFromResource(Context context) {
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



    public static KeyPair generateAndSaveKeyPairToFiles(Context context) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();

            try (ObjectOutputStream privateOos = new ObjectOutputStream(context.openFileOutput(PRIVATE_KEY_FILE, Context.MODE_PRIVATE))) {
                privateOos.writeObject(keyPair.getPrivate());
            }

            try (FileOutputStream fos = context.openFileOutput(PUBLIC_KEY_FILE, Context.MODE_PRIVATE);
                 ObjectOutputStream publicOos = new ObjectOutputStream(fos)) {
                publicOos.writeObject(keyPair.getPublic());
            }

            return keyPair;
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Failed to generate KeyPair", e);
        }
    }
    public static final String FalconPRIVATE_KEY_FILE = "Falconprivate_key.ser";
    public static final String FalconPUBLIC_KEY_FILE = "Falconpublic_key.ser";
    public static KeyPair generateAndSaveFalconKeyPairToFiles(Context context) {
        try {
            KeyPair keyPair = DataEdge.FalconKeyPair();

            try (ObjectOutputStream privateOos = new ObjectOutputStream(context.openFileOutput(FalconPRIVATE_KEY_FILE, Context.MODE_PRIVATE))) {
                privateOos.writeObject(keyPair.getPrivate().getEncoded());
            }

            try (FileOutputStream fos = context.openFileOutput(FalconPUBLIC_KEY_FILE, Context.MODE_PRIVATE);
                 ObjectOutputStream publicOos = new ObjectOutputStream(fos)) {
                publicOos.writeObject(keyPair.getPublic().getEncoded());
            }

            return keyPair;
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Failed to generate KeyPair", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static final String DilithiumPRIVATE_KEY_FILE = "Dilithiumprivate_key.ser";
    public static final String DilithiumPUBLIC_KEY_FILE = "Dilithiumpublic_key.ser";

    public static KeyPair generateAndSaveDilithiumKeyPairToFiles(Context context) {
        try {
            KeyPair keyPair = DataEdge.DilithiumKeyPair();

            try (ObjectOutputStream privateOos = new ObjectOutputStream(context.openFileOutput(DilithiumPRIVATE_KEY_FILE, Context.MODE_PRIVATE))) {
                privateOos.writeObject(keyPair.getPrivate());
            }

            try (FileOutputStream fos = context.openFileOutput(DilithiumPUBLIC_KEY_FILE, Context.MODE_PRIVATE);
                 ObjectOutputStream publicOos = new ObjectOutputStream(fos)) {
                publicOos.writeObject(keyPair.getPublic());
            }

            return keyPair;
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException("Failed to generate KeyPair", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static AsymmetricCipherKeyPair generateAndSaveKyberKeyPairToFiles(Context context) {
        try {
            KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
            keyPairGenerator.init(new KyberKeyGenerationParameters(new SecureRandom(), KyberParameters.kyber1024));

            AsymmetricCipherKeyPair keyPairs = keyPairGenerator.generateKeyPair();

            try (ObjectOutputStream privateOos = new ObjectOutputStream(context.openFileOutput(KYBER_PRIVATE_KEY_FILE, Context.MODE_PRIVATE))) {
                KyberPrivateKeyParameters kyberPrivateKey = (KyberPrivateKeyParameters) keyPairs.getPrivate();
                privateOos.writeObject(kyberPrivateKey.getEncoded());
            }

            try (FileOutputStream fos = context.openFileOutput(KYBER_PUBLIC_KEY_FILE, Context.MODE_PRIVATE);
                 ObjectOutputStream publicOos = new ObjectOutputStream(fos)) {
                KyberPublicKeyParameters kyberPublicKey = (KyberPublicKeyParameters) keyPairs.getPublic();
                publicOos.writeObject(kyberPublicKey.getEncoded());
            }

            return keyPairs;
        } catch (IOException e) {
            throw new RuntimeException("Failed to generate KeyPair", e);
        }
    }
}
