import java.security.SecureRandom;

public class ServerSide {
    private static byte[] challenge=new byte[32];
    public void createChallenge(){
        SecureRandom newchallenge=new SecureRandom();
        newchallenge.nextBytes(challenge);
    }
}
