import java.lang.*;
import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Server extends Thread {

	private ServerSocket servSock = null;

	private void printInfo(Socket s) {
		InetAddress ia;
		System.out.println("\tLocal Port : " + s.getLocalPort());
		System.out.println("\tRemote Port: " + s.getPort());

		ia = s.getInetAddress(); // REMOTE
		System.out.println("\t==> Remote IP: " + ia.getHostAddress());
		System.out.println("\t==> Remote Name: " + ia.getHostName());
		System.out.println("\t==> Remote DNS Name: " + ia.getCanonicalHostName());

		ia = s.getLocalAddress(); // LOCAL
		System.out.println("\t==> Local IP: " + ia.getHostAddress());
		System.out.println("\t==> Local Name: " + ia.getHostName());
		System.out.println("\t==> Local DNS Name: " + ia.getCanonicalHostName());
	}

	public Server(int port) {
		try {
			servSock = new ServerSocket(port, 5);
			System.out.println("Listening on port " + port);
		} catch (Exception e) {
			System.err.println("[ERROR] + " + e);
		}
		this.start();
	}

	public void run() {
		while (true) {
			try {
				// System.out.println("Waiting for connections......");
				Socket s = servSock.accept();
				// System.out.println("Server accepted connection from: " +
				// s.getInetAddress().getHostAddress());
				// printInfo(s);

				new ClientHandler(s).start();
			} catch (Exception e) {
				System.err.println("[ERROR] + " + e);
			}
		}
		// servSock.close(); // At some point we need to close this (when we shutdown
		// the server), for now let's put it here
	}

	public static void main(String args[]) {
		new Server(1234);
	}

}

/**
 * Handles connection with the client.
 */
class ClientHandler extends Thread {
	private Socket s = null;
	private ObjectOutputStream oos = null;
	private ObjectInputStream ois = null;

	public ClientHandler(Socket s) {
		this.s = s;
		try {
			oos = new ObjectOutputStream(s.getOutputStream());
			ois = new ObjectInputStream(s.getInputStream());
		} catch (Exception e) {
			System.err.println("Exception: " + e);
		}
	}

	public void run() {
		try {
			
			RSA key = new RSA(40);
			BigInteger myPubKeyE = key.get_publicKey();
			BigInteger myMod= key.get_modulus();

			
			//Send public key info to client.
			oos.writeObject(myPubKeyE);

			oos.writeObject(myMod);


			//Get public key info from client.
			BigInteger otherPubKeyE = (BigInteger) ois.readObject();
			BigInteger otherMod = (BigInteger) ois.readObject();

			
			
			//Encrypt message
			String myMessage = "Help";
			System.out.println("I am encrypting and sending this to the client: "+ myMessage);
			int CHUNK_LEN = 3;
			int sendCount = myMessage.length()/CHUNK_LEN;
			oos.writeObject(sendCount+1);//sends how many chunks are going to be coming
			
			int chunkCount= (int) ois.readObject();
			System.out.println("Getting "+ chunkCount + " encrypted chunks.");

			String[] myChunks = new String[sendCount+1];
			for(int i = 0; i<myChunks.length; i++){
				if((i+1)*CHUNK_LEN >= myMessage.length()){
					myChunks[i] = myMessage.substring((i*CHUNK_LEN));
					if (myChunks[i]==""){
						myChunks[i]=" ";//Hack that prevents errors when converting to BigInt
					}
				}else{
					myChunks[i] = myMessage.substring((i*CHUNK_LEN), (i+1)*CHUNK_LEN);
				}
			}
			//myChunks should have all of the string broken into chunks
			
			for(int i = 0; i<myChunks.length;i++){
				byte[] myMesBytes = myChunks[i].getBytes();
				BigInteger myMess = new BigInteger(myMesBytes);
				BigInteger encrypted = myMess.modPow(otherPubKeyE, otherMod);
				//Send message to Server
				oos.writeObject(encrypted);
			}
			
			

			

			//Get encrypted message from Server
			String finalString = "";
			for(int i = 0; i<chunkCount; i++){
				BigInteger otherCrypt = (BigInteger) ois.readObject();
				BigInteger otherDecrypt = key.decrypt(otherCrypt);
				byte[] out = otherDecrypt.toByteArray();
				finalString += new String(out);
			}
			System.out.println("Decrypted Message: "+ finalString);
			/*
			 * Close stream
			 */
			oos.close();
			ois.close();

			/*
			 * Close connection
			 */
			s.close();

		} catch (Exception e) {
			System.err.println("Exception: " + e);
		}
	}
}
