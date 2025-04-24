import java.io.*;
import java.security.*;

public class GeneradorLlaves {
    private static final String KEY_FILE_PUBLIC = "server_public.key";
    private static final String KEY_FILE_PRIVATE = "server_private.key";
    private static final int KEY_SIZE = 1024;
    
    public static void main(String[] args) {
        try {
            System.out.println("Generando par de llaves RSA de " + KEY_SIZE + " bits.......");
            
            // Generamos el  par de llaves RSA!
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEY_SIZE);
            KeyPair keyPair = keyGen.generateKeyPair();
            
            // Guardamos le llave pública
            ObjectOutputStream publicKeyOut = new ObjectOutputStream(new FileOutputStream(KEY_FILE_PUBLIC));
            publicKeyOut.writeObject(keyPair.getPublic());
            publicKeyOut.close();
            
            // Guardamos la llave privada
            ObjectOutputStream privateKeyOut = new ObjectOutputStream(new FileOutputStream(KEY_FILE_PRIVATE));
            privateKeyOut.writeObject(keyPair.getPrivate());
            privateKeyOut.close();
            
            System.out.println("Llaves generadas y guardadas exitosamente:");
            System.out.println("Llave pública: " + KEY_FILE_PUBLIC);
            System.out.println("Llave privada: " + KEY_FILE_PRIVATE);
            
        } catch (Exception e) {
            System.err.println("Error generando las llaves: " + e.getMessage());
            //e.printStackTrace();
        }
    }
}