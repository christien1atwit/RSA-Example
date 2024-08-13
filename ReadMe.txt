Nathan Christie 8/1/24

To use the program, simply run Server.java, and then Client.java
Both will display: Plaintext of message they are sending, How many encrypted chunks they are getting, the final decrypted message from the other side.

Both Server.java and Client.java use RSA.java to generate their public and private keys, and to decrypt messages.

How message exchange happens:
1. The length of the Plaintext message is divided by 3 to get how many chunks it will be sent in
2. The number of chunks is sent to the recipient
3. This length is then used to initalize an array that will hold the substring chunks of Plaintext
4. The Plaintext message is then broken into chunks of 3 character substrings (final chunk may be of a smaller length)
5. The Plaintext chunks are then encrypted using the recipient's public key and sent
6. Each time a chunk is recieved the chunk is decrypted using the private key, then it is appended to a string
7. The recipient stops looking for more chunks after it has gotten the number it was told earlier

Changing the chunk size to be larger may result in text becoming corrupt!