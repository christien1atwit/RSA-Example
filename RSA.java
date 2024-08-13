/*************************************************************************
 *  Compilation:  javac RSA.java
 *  Execution:    java RSA N
 *
 *  N represents the number of bits of the modulus.
 *
 *************************************************************************/

import java.math.BigInteger;
import java.security.SecureRandom;


public class RSA {
   private final static SecureRandom random = new SecureRandom();

   private BigInteger privateKey;
   private BigInteger publicKey;
   private BigInteger modulus;        //   p * q = modulus

   private BigInteger p;
   private BigInteger q; 
   private BigInteger phi;

   RSA(int N) {
      p = BigInteger.probablePrime(N/2, random);
      q = BigInteger.probablePrime(N/2, random);
      phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

      modulus    = p.multiply(q);
      publicKey  = new BigInteger("65537");     // common value in practice = 2^16 + 1
      privateKey = publicKey.modInverse(phi);
   }


   BigInteger get_publicKey(){
      return publicKey;
   }
   BigInteger get_modulus(){
      return modulus;
   }

   BigInteger encrypt(BigInteger message) {
      return message.modPow(publicKey, modulus);
   }

   BigInteger decrypt(BigInteger encrypted) {
      return encrypted.modPow(privateKey, modulus);
   }

   public String toString() {
      String s = "----- KEY INFORMATION -----\n";
      s += "p = " + p + " (" + p.bitLength() + " bits) \n";
      s += "q = " + q + " (" + q.bitLength() + " bits) \n";
      s += "phi = " + phi + " (" + phi.bitLength() + " bits) \n";
      s += "             ----------- \n";
      s += "public  = " + publicKey  + " (" + publicKey.bitLength() +" bits) \n";
      s += "private = " + privateKey + " (" + privateKey.bitLength() +" bits) \n";
      s += "modulus = " + modulus + " (" + modulus.bitLength() +" bits) \n";
      s += "\n---------------------------\n\n";
      return s;
   }


   public static void main(String[] args) {
      int N = Integer.parseInt(args[0]);
      RSA key = new RSA(N);

      System.out.println(key);


      // create random message, encrypt and decrypt
      //BigInteger message = new BigInteger(N-1, random);


      /* 
       * Let's use text as our message.
       * First convert the String into an array of bytes.
       * Then convert the array of bytes into a BigInteger
       */
      String s = "Test";
      byte[] bytes = s.getBytes();
      BigInteger message = new BigInteger(bytes);

      System.out.println("Message to be encrypted: " + s);
      System.out.println("message (as a BigInteger)  = " + message);


      BigInteger encrypt = key.encrypt(message);
      BigInteger decrypt = key.decrypt(encrypt);



      System.out.println("encrpyted = " + encrypt);
      System.out.println("decrypted = " + decrypt);

      /*
      * Since we know that we are dealing with text, let's convert 
      * the BigInteger into a String. 
      * - 1st convert the BigInteger into an array of bytes.
      * - Then convert the array of bytes into a String.
      */
      byte[] b = decrypt.toByteArray();
      System.out.println("Decrypted message as text: " + new String(b));


      ////////////////////////////////////////////////////////////////////
      // Now we are going to First Decrypt and Then Encrypt!
      // Why this still works?

      System.out.println("\n\nNow we are going to First Decrypt and Then Encrypt!");

      decrypt = key.decrypt(message);
      encrypt = key.encrypt(decrypt);
      b = encrypt.toByteArray();
      System.out.println("Decrypted message as text: " + new String(b));
   }
}
