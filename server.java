import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

class server
{
    public static ServerSocket sockserv=null; // création du serveur
    private static Socket soc; // Socket de communication avec le client
    public static ObjectInputStream in ; // canal d'entrée
    public static ObjectOutputStream out; // canal de sortie
    private static PrivateKey pvtKey; //Clé RSA Privée
    private static Key desKey; //Clé DES du client

    public static void main (String args[]) throws Exception
    {
        String message;
        sockserv = new ServerSocket (1234);
        Scanner scanner = new Scanner(System.in);
        boolean continuer = true;
        try {
            System.out.println("Waiting for client . . .");
            rsaTransmission();
            desReception();
            System.out.println("En attente du message du client . . .");
            while (continuer)
            {
                try
                {
                    soc = sockserv.accept();
                    InputStream inputStream = soc.getInputStream();
                    OutputStream outputStream = soc.getOutputStream();
                    out = new ObjectOutputStream(outputStream); // sortie
                    out.flush();
                    in = new ObjectInputStream(inputStream); // flux entrée
                    byte[] byteMessage = (byte[]) in.readObject(); // ?
                    message = decryptMessage(byteMessage);
                    String[] messageSplit = message.split(" ");
                    System.out.print("Client : ");
                    System.out.println(message);
                    if (messageSplit[0].equals("QUIT")) {
                        continuer = false;
                        System.out.println("Arrêt du serveur . . .");
                    } else {
                        System.out.print("Entrez votre message : ");
                        message = scanner.nextLine();
                        messageSplit = message.split(" ");
                        byteMessage = encryptMessage(message);
                        out.writeObject(byteMessage);
                        out.flush();
                        if (messageSplit[0].equals("QUIT")) {
                            continuer = false;
                            System.out.println("Arrêt du serveur . . .");
                        }
                    }
                    out.close();
                    in.close();
                    soc.close();
                } catch (IOException ex) {
                    System.out.println(ex);
                }
            }
        } finally {
            try {
                sockserv.close(); // ?
            } catch (IOException ex) { }
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
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
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
        cipher.init(Cipher.DECRYPT_MODE, desKey);
        byte[] decodedMessage = cipher.doFinal(messageEncrypt);
        return new String(decodedMessage, StandardCharsets.UTF_8);
    }

    /**
     * Récupère la clé DES et la décrypte à l'aide de la clé privé
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws ClassNotFoundException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private static void desReception() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        soc = sockserv.accept();
        InputStream inputStream = soc.getInputStream();
        ObjectInputStream dataInputStream = new ObjectInputStream(inputStream);

        byte[] decodedBytes = (byte[]) dataInputStream.readObject();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, pvtKey);
        byte [] decodedDesKey = cipher.doFinal(decodedBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        desKey = factory.generateSecret(new DESKeySpec(decodedDesKey));
        soc.close();
    }

    /**
     * Génère la pair de clé RSA et transmet la clé publique
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private static void rsaTransmission() throws IOException, NoSuchAlgorithmException {
        soc = sockserv.accept();
        System.out.println("Client connected");
        OutputStream outputStream = soc.getOutputStream();
        ObjectOutputStream dataOutputStream = new ObjectOutputStream(outputStream);

        KeyPairGenerator RSAKeyGen = KeyPairGenerator.getInstance("RSA");
        RSAKeyGen.initialize(1024);
        KeyPair pair = RSAKeyGen.generateKeyPair();
        PublicKey clePub = pair.getPublic();
        pvtKey = pair.getPrivate();

        dataOutputStream.writeObject(clePub);
        dataOutputStream.flush();
        soc.close();
    }
}