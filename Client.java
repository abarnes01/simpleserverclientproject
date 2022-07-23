import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import javax.crypto.Cipher;

public class Client {

    public static void main(String[] args) throws Exception {
        // args: host, port, userid
        
        String userid = args[2];
        Socket socket = null;
        ObjectOutputStream oout = null;
        ObjectInputStream oin = null;

        try { // attempt connection
            socket = new Socket(args[0], Integer.parseInt(args[1]));

            oin = new ObjectInputStream(socket.getInputStream());
            Integer postSize = (Integer)oin.readObject(); // amount of posts to read
            if (postSize != 0) {
                for (int i = 0; i < postSize; i++) {
                    String senderUid = (String)oin.readObject();
                    String message = (String)oin.readObject();
                    Date timestamp = (Date)oin.readObject();
                    System.out.println("Sender: " + senderUid);
                    System.out.println("Date: " + timestamp);
                    try {
                        // decryption
                        FileInputStream fis = new FileInputStream(userid+".prv");
                        ObjectInputStream keyStream = new ObjectInputStream(fis);
                        PrivateKey privateKey = (PrivateKey)keyStream.readObject();
                        keyStream.close();
                        
                        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipher.init(Cipher.DECRYPT_MODE, privateKey);
                        
                        byte[] encryptedBytes = Base64.getDecoder().decode(message);
                        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                        message = new String(decryptedBytes, "UTF8");
                    } catch (Exception e) {
                        // decrypt fails, message displays original form
                    }
                    System.out.println("Message: " + message + "\n");
                }
            }
            oout = new ObjectOutputStream(socket.getOutputStream());
            System.out.println("Do you want to add a post? [y/n]");
            Scanner scanner = new Scanner(System.in);
            String yOrN = scanner.nextLine();
            oout.writeUTF(yOrN);
            if (yOrN.equals("y")) {
                System.out.println("\nEnter the recipient userid: ");
                String rUserid = scanner.nextLine();
                System.out.println("\nEnter your message: ");
                String message = scanner.nextLine();
                Date timestamp = new Date();
                oout.writeUTF(userid);
                if (rUserid.equalsIgnoreCase("all")) {
                    oout.writeUTF(message);
                } else {
                    try {
                        // encryption
                        FileInputStream fis = new FileInputStream(rUserid+".pub");
                        ObjectInputStream keyStream = new ObjectInputStream(fis);
                        PublicKey publicKey = (PublicKey)keyStream.readObject();
                        keyStream.close();

                        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
                        message = Base64.getEncoder().encodeToString(encryptedBytes);
                    } catch (IOException e) {
                        System.err.println("Key not found exception: Message not encrypted.");
                    }
                    oout.writeUTF(message);
                }
                oout.writeObject(timestamp);
                // signature
                FileInputStream fis = new FileInputStream(userid+".prv");
                ObjectInputStream keyStream = new ObjectInputStream(fis);
                PrivateKey privateKey = (PrivateKey)keyStream.readObject();
                keyStream.close();

                Signature s = Signature.getInstance("SHA1withRSA");
                s.initSign(privateKey);
                s.update(userid.getBytes());
                s.update(message.getBytes());
                s.update(timestamp.toString().getBytes());
                byte[] signature = s.sign();
                oout.writeObject(signature); 
            }
            oout.flush();
            scanner.close();
        } catch (Exception e) {
            System.err.println("Error: Cannot connect to the server.");
        } finally {
            if (socket != null) {
                socket.close();
            }
            if (oout != null) {
                oout.close();
            }
            if (oin != null) {
                oin.close();
            }
        }
    }
}
