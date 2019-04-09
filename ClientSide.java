import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientSide {
    private String crt_path;
    private PublicKey server;
    private PublicKey CA;
    private X509Certificate CAcert;
    private static byte[] nonce=new byte[32];


    public ClientSide(String crt_path){
        this.crt_path=crt_path;
        CAcert = null;
        this.server=null;
    }

    public X509Certificate get_Cert_object() {
        InputStream fis=null;
        CertificateFactory cf;
        try {
            fis = new FileInputStream(crt_path);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            cf = CertificateFactory.getInstance("X509");
            CAcert = (X509Certificate) cf.generateCertificate(fis);
        } catch (CertificateException ce) {
            ce.getCause();
        }

        return CAcert;
    }

    public PublicKey getServer() {
        this.server=CAcert.getPublicKey();
        return this.server;
    }
    /*
        nonce is used to prevent replay attacks, so that the attacker will see the nonce and the hash and have to validate both
        Since a new nonce is created each time with client nonce, implementation,
        the hash value of (challenge+nonce+password) that the attacker
        gets will be different instead even though the attacker can get the challenge
        The protocol becomes:
            1. server sends a random challenge c
            2. client chooses a nonce n (should be distinct every time)
            3. client sends n || h(c || n || p)
            4. server recomputes h(c || n || p) (using the p from its database)
               and sees if this value matches what the client sent
     */

    public void createNonce(){
        SecureRandom randombytes=new SecureRandom();
        randombytes.nextBytes(nonce);
    }
    public byte[] getNonce(){
        return nonce;
    }
    public byte[] decryptNonce(byte[] nonce){
        byte[] freshnonce=new byte[32];
        try {
            Cipher todecrypt = Cipher.getInstance("RSA/ECB/PKCS5Padding");
            todecrypt.init(Cipher.DECRYPT_MODE, server);

            freshnonce=todecrypt.doFinal(nonce);
        }catch(Exception e){
            e.printStackTrace();
        }
        return freshnonce;


    }

}
