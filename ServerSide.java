package ass2;

import javax.crypto.Cipher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerSide {


    private PrivateKey serverPrivateKey = null;
    private static byte[] challenge = new byte[32];

    public PrivateKey getPrivateKey(String privateKeyPath) throws Exception {
        Path path = Paths.get(privateKeyPath);
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    public void setServerPrivateKey(PrivateKey pvk) {
        this.serverPrivateKey = pvk;
    }

    public PrivateKey getServerPrivateKey() {
        return this.serverPrivateKey;
    }

    public byte[] decryptFileName(byte[] encryptedFileName) throws Exception {
        Cipher toDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        toDecrypt.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] decryptedFileName = toDecrypt.doFinal(encryptedFileName);
        return decryptedFileName;
    }

    public byte[] decryptFileChunk(byte[] fileBuffer) throws Exception {
        Cipher decryptBuffer = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptBuffer.init(Cipher.DECRYPT_MODE, getServerPrivateKey());
        return decryptBuffer.doFinal(fileBuffer);
    }


}
