package ass2;

import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


//encrypt the file here before sending
public class ClientWithoutSecurity {

    public static void main(String[] args) {

        String filename = "rr.txt";
        if (args.length > 0) filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1) filename = args[1];

        int port = 4321;
        if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
        ClientSide protocols = new ClientSide();

        BufferedReader stringtoServer = null;
        PrintWriter writeToServer = null;
        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            //receiving the encrypted message

            //generating and sending the nonce
            protocols.createNonce();
            byte[] generated_nonce = protocols.getNonce();
            toServer.write(generated_nonce);
            System.out.println("Nonce sent!");


            //TODO: receive the nonce (use while loop to receive all the bytes as the file may be large)
            int sizeofnonce = fromServer.readInt();
            byte[] receivedNonce = new byte[sizeofnonce];
            fromServer.readFully(receivedNonce);
            System.out.println("Nonce received!");
            //TODO: request servers signed certificate
            try {
                writeToServer = new PrintWriter(clientSocket.getOutputStream(), true);
                System.out.println("Sending request");
                writeToServer.println("Give me your certificate!");
                writeToServer.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }


            System.out.println("request for certificate sent");
            //TODO: receive signed certificate and validate
            int certLength = fromServer.readInt();
            System.out.println("Cert length " + certLength);
            byte[] receivedCert = new byte[certLength];
            fromServer.readFully(receivedCert);
            System.out.println("Certificate received");

            // Extract CA's public key from CACSE.crt
//			InputStream is=new FileInputStream("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\cacse.crt");
            protocols.setCrt_path("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\cacse.crt");
            X509Certificate cacert = protocols.get_Cert_object(); //get x509cert oject from cacse.crt
            PublicKey pbkey = cacert.getPublicKey();
            System.out.println("Extracted public key");


            //transform byte to cert
            InputStream ins = new ByteArrayInputStream(receivedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) certFactory.generateCertificate(ins);

//            System.out.println(cert);

            //check validity and verify of Server's cert with CA's public key
            serverCert.checkValidity();
            System.out.println("Cert valid");
            serverCert.verify(pbkey);
            System.out.println("Cert verified");

            //TODO: Extract Server public key and get nonce and check nonce
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
                writeToServer.println("Bye, you liar");
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
            encryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);









            //TODO: send confirmation of server ID
            //TODO: receive newly sent nonce from server
            //TODO: request servers signed certificate
            //TODO: encrypt nonce with private key
            //TODO: give server public key
            //TODO: send public key
            //TODO: receive confirmation message from server


//            System.out.println("Sending file...");
//            // Send the filename
//            toServer.writeInt(0);
//            toServer.writeInt(filename.getBytes().length);
//            toServer.write(filename.getBytes());
//            //toServer.flush();
//
//            // Open the file
//            fileInputStream = new FileInputStream(filename);
//            bufferedFileInputStream = new BufferedInputStream(fileInputStream);
//
//            byte[] fromFileBuffer = new byte[117];
//
//            // Send the file
//            for (boolean fileEnded = false; !fileEnded; ) {
//                numBytes = bufferedFileInputStream.read(fromFileBuffer);
//                fileEnded = numBytes < 117;
//
//                toServer.writeInt(1);
//                toServer.writeInt(numBytes);
//                toServer.write(fromFileBuffer);
//                toServer.flush();
//            }
//
//            bufferedFileInputStream.close();
//            fileInputStream.close();
//
//            System.out.println("Closing connection...");
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        long timeTaken = System.nanoTime() - timeStarted;
//        System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static byte[] toByteArray(DataInputStream dis) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        byte[] bytes = new byte[1024];
        int len;
        while ((len = dis.read()) != -1) {
            output.write(bytes);
        }
        return output.toByteArray();
    }
}


