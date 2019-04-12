package ass2;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CP2Client {

    private static String filename = "w8_network_whiteboard_notes.pdf";
    private static String filepath = "C:\\Users\\It'sMine\\Desktop\\SUTD\\Term 5\\50.005  Computer System Engineering\\w8_network_whiteboard_notes.pdf";
    private static String CACSEcrtPath = "C:\\Users\\It'sMine\\AndroidStudioProjects\\JavaTest\\Javatest\\src\\main\\java\\ass2\\cacse.crt";
    private static String serverAddress = "localhost";
    private static int port = 4321;


    public static void main(String[] args) {

        if (args.length > 0) filename = args[0];

        if (args.length > 1) serverAddress = args[1];

        if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        // initialise required connections
        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
        ClientSide protocols = new ClientSide();            // ClientSide is a class with helper functions

        BufferedReader stringtoServer = null;
        PrintWriter writeToServer = null;

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            //generating and sending the nonce
            protocols.createNonce();
            byte[] generated_nonce = protocols.getNonce();
            toServer.write(generated_nonce);
            System.out.println("Nonce sent!");

            //receive the nonce
            int sizeofnonce = fromServer.readInt();
            byte[] receivedNonce = new byte[sizeofnonce];
            fromServer.readFully(receivedNonce);
            System.out.println("Nonce received!");

            //request for server's signed certificate
            try {
                writeToServer = new PrintWriter(clientSocket.getOutputStream(), true);
                System.out.println("Sending request");
                writeToServer.println("Give me your certificate!");
                writeToServer.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }


            System.out.println("Request for certificate sent");

            //receive signed certificate and validate
            int certLength = fromServer.readInt();
            System.out.println("Certificate length :" + certLength);
            byte[] receivedCert = new byte[certLength];
            fromServer.readFully(receivedCert);
            System.out.println("Certificate received");

            // Extract CA's public key from CACSE.crt
            protocols.setCrt_path(CACSEcrtPath);
            X509Certificate cacert = protocols.get_Cert_object();           //get x509cert oject from cacse.crt
            PublicKey pbkey = cacert.getPublicKey();
            System.out.println("Extracted public key");

            // transform byte to cert
            InputStream ins = new ByteArrayInputStream(receivedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) certFactory.generateCertificate(ins);

            //check validity and verify of Server's cert with CA's public key
            serverCert.checkValidity();
            System.out.println("Certificate is valid");
            serverCert.verify(pbkey);
            System.out.println("Certificate is verified");

            // Extract Server's public key and get nonce and check nonce
            PublicKey serverPublicKey = serverCert.getPublicKey();
            protocols.setCAcert(serverCert);
            protocols.setServerKey(serverPublicKey);
            byte[] serverNonce = protocols.decryptNonce(receivedNonce);
            Boolean nonceCheck = protocols.checkNonce(serverNonce, generated_nonce);

            // if nonce check passed
            if (nonceCheck) {
                System.out.println("Server check passed (AP passed)");
                writeToServer.println("Handshake for file upload");
                writeToServer.flush();
            } else {       // if nonce check failed, send bye message and close all connections
                System.out.println("Server check failed (AP failed)");
                writeToServer.println("Bye, you liar :<");
                writeToServer.flush();
                // close all connections
                toServer.close();
                fromServer.close();
                writeToServer.close();
                clientSocket.close();
            }

            // Start file transfer
            System.out.println("Sending file...");

            // start time counter
            long timeStarted = System.nanoTime();

            // Initialise RSA cipher using server's public key
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, protocols.getServerKey());

            // generate a session key (AES, keysize = 128bits)
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey sessionKey = keyGen.generateKey();

            // encrypt session key with server's public key
            byte[] sessionKeyBytes = sessionKey.getEncoded();
            byte[] encryptedSessionKey = encryptCipher.doFinal(sessionKeyBytes);

            // send encrypted session key
            toServer.writeInt(encryptedSessionKey.length); //write to server key length
            toServer.write(encryptedSessionKey);
            toServer.flush();
            System.out.println("Sent Session Key to Server!");

            // initialise cipher using session key for file encryption
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);

            // send encrypted file name
            System.out.println("1. Sending filename");
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            byte[] encryptedFileName = sessionCipher.doFinal(filename.getBytes());
            toServer.writeInt(encryptedFileName.length);
            toServer.write(encryptedFileName);
            toServer.flush();
            System.out.println("Filename sent!");

            // send encrypted file
            File file = new File(filepath);
            byte[] fileBytes = new byte[(int) file.length()];      // convert to byte array for encryption
            BufferedInputStream bufins = new BufferedInputStream(new FileInputStream(file));
            bufins.read(fileBytes, 0, (int) file.length());
            byte[] encryptedFile = sessionCipher.doFinal(fileBytes);    // encrypt

            toServer.writeInt(1);
            toServer.writeLong(file.length());
            toServer.writeLong(encryptedFile.length);              //send over file size
            toServer.write(encryptedFile);
            toServer.flush();
            System.out.println("Sent File to Server!");


            // record time taken
            long timeTaken = System.nanoTime() - timeStarted;
            System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");

            // close all connections
            toServer.close();
            fromServer.close();
            writeToServer.close();
            clientSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
