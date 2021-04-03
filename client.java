import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import static java.lang.System.exit;

public class client {

    /**
     * socket pour communiquer avec un client
     */
    public static Socket sockcli = null;

    /**
     * Socket utilisé pour l'échange des clés
     */
    private static Socket soc;

    /**
     * réception des informations en provenance du serveur
     */
    public static ObjectInputStream in;

    /**
     * envoi d'informations vers le serveur
     */
    public static ObjectOutputStream out;

    /**
     * Clé RSA Public du serveur
     */
    private static PublicKey serverPubKey;

    /**
     * Clé DES
     */
    private static Key key;

    public static void main(String args[]) throws Exception {
        String message;
        Scanner scanner = new Scanner(System.in);
        boolean continuer = true;
        receivePublicKey();
        transmitDesKey();
        while (continuer) {
            try {
                sockcli = new Socket("127.0.0.1", 1234);
                InputStream inputStream = sockcli.getInputStream();
                OutputStream outputStream = sockcli.getOutputStream();
                out = new ObjectOutputStream(outputStream); // sortie
                out.flush();
                in = new ObjectInputStream(inputStream); // flux entrée
                System.out.print("Entrez votre message : ");
                message = scanner.nextLine();
                String[] messageSplit = message.split("");
                byte[] byteMessage = encryptMessage(message);
                out.writeObject(byteMessage); // ecriture socket
                out.flush();
                if (messageSplit[0].equals("QUIT")) {
                    continuer = false;
                    System.out.println("Arrêt du serveur . . .");
                } else {
                    byteMessage = (byte[]) in.readObject(); // lecture socket
                    message = decryptMessage(byteMessage);
                    messageSplit = message.split("");
                    if (messageSplit[0].equals("QUIT")) {
                        continuer = false;
                        System.out.println("Arrêt du serveur . . .");
                        exit(0);
                    }
                    System.out.print("Message reçus : ");
                    System.out.println(message);
                }
                out.close();
                in.close();
                sockcli.close();
            } catch (IOException ex) {
                System.out.println(ex);
            }
        }

    }

    /**
     * Encrypte le message passé en paramètre
     * @param mess
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     */
    private static byte[] encryptMessage(String mess) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] messageDecode = mess.getBytes(StandardCharsets.UTF_8);
        return cipher.doFinal(messageDecode);
    }

    /**
     * Décrypte le message crypté passé en paramètre
     * @param messageEncrypt
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     */
    private static String decryptMessage (byte[] messageEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte [] decodedMessage = cipher.doFinal(messageEncrypt);
        return new String(decodedMessage, StandardCharsets.UTF_8);
    }

    /**
     * Génère la clé DES, la crypte à l'aide de la clé public transmise par le serveur puis lui envoi
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws IOException
     */
    private static void transmitDesKey() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException {
        soc = new Socket("127.0.0.1", 1234);
        OutputStream outputStream = soc.getOutputStream();
        ObjectOutputStream dataOutputStream = new ObjectOutputStream(outputStream);

        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56); // 56 = valeur imposée
        key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, serverPubKey);
        byte[] code = cipher.doFinal(key.getEncoded());
        dataOutputStream.writeObject(code);
        dataOutputStream.flush();
        soc.close();
    }

    /**
     * Récupère la clé public envoyée par le serveur
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ClassNotFoundException
     */
    private static void receivePublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException {
        soc = new Socket("127.0.0.1", 1234);
        InputStream inputStream = soc.getInputStream();
        ObjectInputStream dataInputStream = new ObjectInputStream(inputStream);

        serverPubKey = (PublicKey) dataInputStream.readObject();
        soc.close();
    }

}