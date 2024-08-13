import java.lang.*;
import java.io.*;
import java.net.*;
import java.math.BigInteger;
import java.security.SecureRandom;

class Client {
	private int a = 3;
	private int q = 353;

	public static void main(String args[]) {
		try {
			//
			// Instead of "localhost", you can pass the IP address of the server
			// The port number the server is listening on is: 1234 (see server code).
			//
			Socket s = new Socket("localhost", 1234);


			ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

			RSA key = new RSA(40);
			BigInteger myPubKeyE = key.get_publicKey();
			BigInteger myMod= key.get_modulus();

			//Get public key info from server.
			BigInteger otherPubKeyE= (BigInteger) ois.readObject();

			BigInteger otherMod= (BigInteger) ois.readObject();

			//Send Server public key info
			oos.writeObject(myPubKeyE);
			oos.writeObject(myMod);
			
			//Prepare message to be chunked and sent
			String myMessage = "Hello World! I Love RSA";
			System.out.println("I am encrypting and sending this to the server: "+ myMessage);

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
			
			//convert decrypted message to text
			
			System.out.println("Decrypted Message: "+ finalString);

			

			// close streams
			oos.close();
			ois.close();

			/*
			 * Close connection
			 */
			s.close();
		} catch (Exception e) {
			System.err.print("[ERROR] ::" + e);
		}
	}
}
