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
public class ServerWithoutSecurity {
	//When client has something to pass, it will connect to the server, handshake and perform upload
	//must handle arbitrary files
	//Use tcp sockets for connecting
	//Use certificate for verification between client and server

	/**
	1) SecStore$ uses$ OpenSSL$ to$ generate$ its$ RSA$ private$ and$ public$ key$
	pair$ (use$1024Lbit$keys).$Using$OpenSSL$ also,$ it$ submits$ the$ public$
	key$and$other$credentials$(e.g.,$its$legal$name)$to$create$a$certificate(
	signing(request$and$stores$it$in$a$file.$

	2) SecStore$uploads$the$certificate$request$to$for$access$by$CSELCA.$!CSEI
	CA!will! verify! the! request,1!sign! it! to! create! a! certificate,! and! passes! the!
	signed! certificate! to! SecStore.! This! certificate! is!now! bound! to! SecStore!
	and!contains!its!public!key.!!

	3) SecStore$ retrieves$ the$ signed$ certificate$ by$ CSELCA.$ When$ people$
	(e.g.,$ a$ client$ program)$ later$ ask$ SecStore$ for$ its$ public$ key,$ it$
	provides$this$signed$certificate.$$

	 Part 1: what is wrong with the diagram? The public key should be sent over to the server for a handshake
	 before the private key is being decrypted.
	 **/
	public static void main(String[] args) {

    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;


		BufferedReader bread=null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			BufferedReader readFromClient=new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

			//Encrypt message with private key

			//get private key from .der file
			Path path = Paths.get("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\example.org.der");
			byte[] privKeyByteArray = Files.readAllBytes(path);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
//			System.out.println(myPrivKey);
			byte[] buffer =new byte[32];
			//get our nonce from client
			fromClient.readFully(buffer);
			System.out.println("Got nonce from client");


			//encrypt nonce
			Cipher encryptMessageToClient=Cipher.getInstance("RSA");
			encryptMessageToClient.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] encryptednonce=encryptMessageToClient.doFinal(buffer);
			toClient.writeInt(encryptednonce.length);
			System.out.println("Nonce length transferred");
			toClient.flush();
			toClient.write(encryptednonce);
			System.out.println("Nonce transferred");
			toClient.flush();

			String certreq=readFromClient.readLine();

			//TODO:send certificate
			if(certreq.equals("Give me your certificate!")) {
				System.out.println("Preparing cert");
				File certificate = new File("C:\\Users\\Me\\IdeaProjects\\progassig2\\src\\example.org.crt");
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
			ServerSide sprotocols=new ServerSide();
//			byte[] newChallenge=sprotocols.createChallenge();












			//Secure handshake should be done here
			Scanner s=new Scanner(fromClient);
			String output = s.hasNext() ? s.next() : "";
			System.out.println(output);




			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}


}
