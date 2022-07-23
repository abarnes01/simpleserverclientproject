import java.net.Socket;
import java.security.PublicKey;
import java.security.Signature;
import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

public class Server {
    
    static class Post {
        String userid;
        String message;
        Date timestamp;

        Post(String uid, String msg, Date ts) {
            userid = uid;
            message = msg;
            timestamp = ts;
        }
    }
    
    public static void main(String[] args) throws Exception {
        Collection<Post> posts = new ArrayList<Post>();
        
        ServerSocket serverSocket = new ServerSocket(Integer.parseInt(args[0])); // constantly running
        System.out.println("Waiting for an incoming connection...");

        while (true) { // keep looking for connections

            try {
                Socket socket = serverSocket.accept();

                ObjectOutputStream oout = new ObjectOutputStream(socket.getOutputStream());
                oout.writeObject(posts.size()); // to alert user x times to read a post object
                if (posts.size() != 0) {
                    for (Post post : posts) {
                        oout.writeObject(post.userid);
                        oout.writeObject(post.message);
                        oout.writeObject(post.timestamp);
                    }
                }
                oout.flush();

                ObjectInputStream oin = new ObjectInputStream(socket.getInputStream());
                String yOrN = (String)oin.readUTF();
                if (yOrN.equals("y")) {
                    String userid = (String)oin.readUTF();
                    String message = (String)oin.readUTF();
                    Date timestamp = (Date)oin.readObject();
                    byte[] signature = (byte[])oin.readObject();
                    System.out.println("\nIncoming post, with details:");
                    System.out.println("Sender: " + userid);
                    System.out.println("Date: " + timestamp);
                    System.out.println("Message: " + message);
                    // verify signature
                    FileInputStream fis = new FileInputStream(userid+".pub");
                    ObjectInputStream keyStream = new ObjectInputStream(fis);
                    PublicKey publicKey = (PublicKey)keyStream.readObject();
                    keyStream.close();
                    
                    Signature s = Signature.getInstance("SHA1withRSA");
                    s.initVerify(publicKey);
                    s.update(userid.getBytes());
                    s.update(message.getBytes());
                    s.update(timestamp.toString().getBytes());
                    if (s.verify(signature)) {
                        posts.add(new Post(userid, message, timestamp));
                        System.out.println("\nSignature accepted: Post added.");
                    } else {
                        System.err.println("\nSignature rejected: Post discarded.");
                    }
                }
                socket.close();
                oout.close();
                oin.close();
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("\nUser connection lost.\n");
            }
        }
    }
}
