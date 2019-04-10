import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerSide {


    private static byte[] challenge=new byte[32];

    public PrivateKey getPrivateKey() throws IOException {
        byte[] privateKey= Files.readAllBytes(Paths.get("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\privateServer.key"));
        PrivateKey retVal=null; //LOL
        return retVal;
    }

    public void createChallenge(){
        SecureRandom newchallenge=new SecureRandom();
        newchallenge.nextBytes(challenge);
    }


}
