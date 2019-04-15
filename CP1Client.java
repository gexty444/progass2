package ass2;

import javax.crypto.Cipher;

import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


//encrypt the file here before sending
public class CP1Client {

    private static String filename = "1484kb.pdf";
    private static String filepath = "C:\\Users\\It'sMine\\Documents\\GitHub\\progass2\\Files\\1484kb.pdf";
    private static String serverAddress = "10.12.111.24";
    private static String CACSEcrtPath = "C:\\Users\\It'sMine\\AndroidStudioProjects\\JavaTest\\Javatest\\src\\main\\java\\ass2\\cacse.crt";
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
        ClientSide protocols = new ClientSide();        // ClientSide is a class with helper functions

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

            // receive the nonce
            int sizeofnonce = fromServer.readInt();
            byte[] receivedNonce = new byte[sizeofnonce];
            fromServer.readFully(receivedNonce);
            System.out.println("Nonce received!");

            // request server's signed certificate
            try {
                writeToServer = new PrintWriter(clientSocket.getOutputStream(), true);
                System.out.println("Sending request");
                writeToServer.println("Give me your certificate!");
                writeToServer.flush();
            } catch (IOException e) {
                e.printStackTrace();
            }

            System.out.println("request for certificate sent");

            //receive signed certificate and validate
            int certLength = fromServer.readInt();
            System.out.println("Cert length " + certLength);
            byte[] receivedCert = new byte[certLength];
            fromServer.readFully(receivedCert);
            System.out.println("Certificate received");

            // Extract CA's public key from CACSE.crt
            protocols.setCrt_path(CACSEcrtPath);
            X509Certificate cacert = protocols.get_Cert_object(); //get x509cert oject from cacse.crt
            PublicKey pbkey = cacert.getPublicKey();
            System.out.println("Extracted public key");


            // transform byte to cert
            InputStream ins = new ByteArrayInputStream(receivedCert);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate serverCert = (X509Certificate) certFactory.generateCertificate(ins);

            //check validity and verify of Server's cert with CA's public key
            serverCert.checkValidity();
            System.out.println("Cert valid");
            serverCert.verify(pbkey);
            System.out.println("Cert verified");

            // Extract Server public key and get nonce and check nonce
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
            encryptCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            // obtains bytes from a file
            fileInputStream = new FileInputStream(filepath);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            // send the file size over
            System.out.println("Sending file length");
            int filelength = fileInputStream.available();
            toServer.writeInt(filelength); //send the file size over
            toServer.flush();

            // Send over file name encrypted with public key.
            System.out.println("1. Sending filename");
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);      //sending filename length
            byte[] encryptedFileName = encryptCipher.doFinal(filename.getBytes());
            toServer.writeInt(encryptedFileName.length);        //sending encrypted file name length
            toServer.write(encryptedFileName);                  //sending encrypted file name
            toServer.flush();
            System.out.println("Filename sent!");

            // Open the file
            System.out.println("2. Preparing File");
            toServer.writeInt(filelength);                      //sending file length

            byte[] fromFileBuffer = new byte[117];

            // Send the file
            int count = 0;
            for (boolean fileEnded = false; !fileEnded; ) {
                System.out.println("Sending file chunk " + count);

                //reads specified number of bytes into the byte array
                numBytes = bufferedFileInputStream.read(fromFileBuffer);

                // Encrypt file buffer
                byte[] encryptedBuffer = protocols.encryptFileBuffer(fromFileBuffer);
                fileEnded = numBytes < 117;

                toServer.writeInt(1);
                //encrypted buffer length is not same as original length
                toServer.writeInt(numBytes);
                toServer.writeInt(encryptedBuffer.length);
                toServer.write(encryptedBuffer);
                toServer.flush();
                count++;

            }
            System.out.println("File Sent");
            while (fromServer.readInt() != 4) {
            }

            // record time taken
            long timeTaken = System.nanoTime() - timeStarted;
            System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Closing connection...");

            // close all remaining connections
            toServer.close();
            fromServer.close();
            writeToServer.close();
            clientSocket.close();

        } catch (Exception e) {
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


