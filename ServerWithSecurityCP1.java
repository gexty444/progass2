package ass2;

import javax.crypto.Cipher;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

//SecStore, leave file as a stream of bytes
public class ServerWithSecurityCP1 {

    private static int port = 4321;
    private static String privateKeyPath = "C:\\Users\\It'sMine\\AndroidStudioProjects\\JavaTest\\Javatest\\src\\main\\java\\ass2\\example.org.der";
    private static String serverCertPath = "C:\\Users\\It'sMine\\AndroidStudioProjects\\JavaTest\\Javatest\\src\\main\\java\\ass2\\example.org.crt";


    public static void main(String[] args) {

        if (args.length > 0) port = Integer.parseInt(args[0]);

        // initialise required connections
        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;
        BufferedReader bread = null;
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        ServerSide serverProtocols = new ServerSide();      // ServerSide is a class with helper functions

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            BufferedReader readFromClient = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

            // get private key
            PrivateKey privateKey = serverProtocols.getPrivateKey(privateKeyPath);
            serverProtocols.setServerPrivateKey(privateKey);

            // get the nonce from client
            byte[] buffer = new byte[32];
            fromClient.readFully(buffer);
            System.out.println("Got nonce from client");

            // encrypt nonce with server's private key and send back
            Cipher encryptMessageToClient = Cipher.getInstance("RSA");
            encryptMessageToClient.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptednonce = encryptMessageToClient.doFinal(buffer);
            toClient.writeInt(encryptednonce.length);
            System.out.println("Nonce length transferred");
            toClient.flush();
            toClient.write(encryptednonce);
            System.out.println("Nonce transferred");
            toClient.flush();

            // client requests for certificate
            String certreq = readFromClient.readLine();

            // send certificate to client
            if (certreq.equals("Give me your certificate!")) {
                System.out.println("Preparing cert");
                File certificate = new File(serverCertPath);
                byte[] certByte = new byte[(int) certificate.length()];
                try {
                    FileInputStream fis = new FileInputStream(certificate);
                    fis.read(certByte);
                    fis.close();

                } catch (IOException ioExp) {
                    ioExp.printStackTrace();
                }
                toClient.writeInt(certByte.length);
                toClient.flush();
                toClient.write(certByte);
                toClient.flush();
                System.out.println("Cert sent");
            }

            // receive message from client (whether AP passed or failed)
            String APresult = readFromClient.readLine();
            if (APresult.equals("Bye, you liar :<")) {
                // we stop, close all connections
                fromClient.close();
                toClient.close();
                readFromClient.close();
                connectionSocket.close();
            }

            // start file transfer
            int fileSize = fromClient.readInt();
            int checksize = 0;
            int datacounter = 0;
            while (checksize < fileSize) {      //cannot exit before finish writing

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    //TODO: Receive filename and decrypt with server's private key
                    System.out.println("Receiving file...");

                    System.out.println("1. Receiving encrypted filename");
                    int numBytes = fromClient.readInt();            //numbytes for decrypted filename is different from encrypted
                    int encryptedFileHeaderLength = fromClient.readInt();
                    byte[] encryptedFilename = new byte[encryptedFileHeaderLength];
                    // Must use read fully!
                    // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                    fromClient.readFully(encryptedFilename, 0, encryptedFileHeaderLength);      //get encrypted file name
                    System.out.println("Received filename!");
                    byte[] decryptedFileName = serverProtocols.decryptFileName(encryptedFilename);
//                    fileOutputStream = new FileOutputStream("C:\\Users\\Me\\Documents\\" + new String(decryptedFileName, 0, numBytes));
                    fileOutputStream = new FileOutputStream(new String(decryptedFileName, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);


                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    System.out.println("2. Reading client output");
                    int numBytes = fromClient.readInt();
                    int encryptedLength = fromClient.readInt();         //get the encrypted buffer length from client
                    /*
                    Need to store all the encrypted bytes into a buffer and slowly decrypt the chunks one by one
                     */
                    byte[] encryptedBlock = new byte[encryptedLength];
                    fromClient.readFully(encryptedBlock, 0, encryptedLength);
                    System.out.println("Received client output");
                    System.out.println("Decrypting data chunks...");
                    byte[] decryptedBlock = serverProtocols.decryptFileChunk(encryptedBlock);
                    System.out.println("Writing to file");
                    if (numBytes > 0) {
                        bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);
                        checksize += numBytes;
                        datacounter++;
                        System.out.println("Writing chunk: " + datacounter);
                    }

                    if (numBytes < 117) {
                        toClient.writeInt(4);
                        toClient.flush();
                        System.out.println("Closing connection...");

                        if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                        if (bufferedFileOutputStream != null) fileOutputStream.close();
                        fromClient.close();
                        toClient.close();
                        connectionSocket.close();
                    }
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


}
