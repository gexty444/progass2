package ass2;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;

public class CP2Server {

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
        ServerSide serverProtocols = new ServerSide();              // ServerSide is a class with helper functions


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
            if (APresult.equals("Bye, you liar")) {
                // we stop, close all connections
                fromClient.close();
                toClient.close();
                readFromClient.close();
                connectionSocket.close();
            }

            // Get encrypted session key and decrypt it
            int length = fromClient.readInt();
            byte[] encryptedSessionKey = new byte[length];
            fromClient.readFully(encryptedSessionKey, 0, length);       //read the session key
            System.out.println("Received Session Key");
            Cipher decryptKey = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptKey.init(Cipher.DECRYPT_MODE, serverProtocols.getPrivateKey(privateKeyPath));
            byte[] byteSessionKey = decryptKey.doFinal(encryptedSessionKey);
            SecretKey sessionKey = new SecretKeySpec(byteSessionKey, "AES");

            int count = 0;

            //Receive file from client
            while (!connectionSocket.isClosed()) {

                Cipher decryptFileName = Cipher.getInstance("AES/ECB/PKCS5Padding");
                decryptFileName.init(Cipher.DECRYPT_MODE, sessionKey);
                int packetType = fromClient.readInt();
                if (packetType == 0) {          // 0 -> file name
                    System.out.println("Receiving file...");

                    System.out.println("1. Receiving encrypted filename");
                    int numBytes = fromClient.readInt();                        //numbytes for decrypted filename is different from encrypted
                    int encryptedFileHeaderLength = fromClient.readInt();       //get length
                    byte[] encryptedFilename = new byte[encryptedFileHeaderLength];
                    fromClient.readFully(encryptedFilename, 0, encryptedFileHeaderLength);  //get encrypted file name
                    System.out.println("Received filename!");

                    // Decrypt file header
                    byte[] decryptedFileName = decryptFileName.doFinal(encryptedFilename);
//                    fileOutputStream = new FileOutputStream("C:\\Users\\Me\\Documents\\" + new String(decryptedFileName, 0, numBytes));
                    fileOutputStream = new FileOutputStream(new String(decryptedFileName, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                    System.out.println("File header Decrypted");


                } else if (packetType == 1) {       // 1 -> file size
                    System.out.println("2. Reading client output");
                    long filelength = fromClient.readLong();
                    long encryptedFileLength = fromClient.readLong();
                    byte[] encryptedFile = new byte[(int) encryptedFileLength];
                    fromClient.readFully(encryptedFile, 0, (int) encryptedFileLength);
                    System.out.println("Received client output");
                    System.out.println("Decrypting file...");
                    byte[] decryptedBlock = decryptFileName.doFinal(encryptedFile);
                    System.out.println("Writing to file");
                    bufferedFileOutputStream.write(decryptedBlock, 0, (int) filelength);
                    count = 1;
                }
                if (count == 1) {
                    System.out.println("Closing connection...");

                    if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                    if (bufferedFileOutputStream != null) fileOutputStream.close();
                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();
                }


            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
