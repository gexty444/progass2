import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;

import static java.nio.file.Files.lines;

public class PrivateKeyTest {

    public static void main(String[] args) throws Exception {
//        String strKeyPEM = "";
//        BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\privateServer.pem"));
//        String line;
//        while ((line = br.readLine()) != null) {
//            strKeyPEM += line + "\n";
//        }
//        br.close();
////        String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\private.pem").toURI())));
////        String privateKeyContent = sb.toString().replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
//        KeyFactory kf=KeyFactory.getInstance("RSA");
//
//        PrivateKey privateKey=kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(sb.toString())));
//        System.out.println(privateKey);
        Path path = Paths.get("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\privateServer.der");
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
        System.out.println(myPrivKey);

    }
}
