import java.io.*;
import java.net.*;
import java.security.*;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ServidorPrincipal {
    private static final int PUERTO = 8888;
    private static final String KEY_FILE_PUBLIC = "server_public.key";
    private static final String KEY_FILE_PRIVATE = "server_private.key";
    
    // Tabla de servicios predefinida
    public static HashMap<String, String[]> tablaServicios = new HashMap<>();
    
    // Variables para la generación de llaves
    public static KeyPair serverKeyPair;
    private static final int KEY_SIZE_RSA = 1024;
    private static final int KEY_SIZE_DH = 1024;
    private static final int KEY_SIZE_AES = 256;
    
    public static void main(String[] args) {
        try {
            // Inicializar tabla de servicios
            inicializarTablaServicios();
            
            // Cargar o generar las llaves del servidor
            cargarOGenerarLlaves();
            
            // Crear servidor socket
            try (ServerSocket serverSocket = new ServerSocket(PUERTO)) {
                System.out.println("Servidor principal iniciado en el puerto " + PUERTO);
                
                // Número de delegados concurrentes (modificar según necesidad)
                int numDelegados = 4; // Valores posibles: 4, 16, 32, 64
                ExecutorService pool = Executors.newFixedThreadPool(numDelegados);
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("Nuevo cliente conectado desde " + clientSocket.getInetAddress().getHostAddress());
                    pool.execute(new ServidorDelegado(clientSocket));
                }
            } catch (Exception e) {
                System.err.println("Error en servidor principal: " + e.getMessage());
                //e.printStackTrace();
            }
            
        } catch (Exception e) {
            System.err.println("Error en servidor principal: " + e.getMessage());
            //e.printStackTrace();
        }
    }
    
    public static int getKeySizeDh() {
        return KEY_SIZE_DH;
        
    }

    private static void inicializarTablaServicios() {
        tablaServicios.put("S1", new String[]{"Estado vuelo", "IPS1", "PS1"});
        tablaServicios.put("S2", new String[]{"Disponibilidad vuelos", "IPS2", "PS2"});
        tablaServicios.put("S3", new String[]{"Costo de un vuelo", "IPS3", "PS3"});
    }
    
    private static void cargarOGenerarLlaves() throws Exception {
        File publicKeyFile = new File(KEY_FILE_PUBLIC);
        File privateKeyFile = new File(KEY_FILE_PRIVATE);
        
        if (publicKeyFile.exists() && privateKeyFile.exists()) {
            PublicKey publicKey;
            try ( // Cargar llaves existentes
                    ObjectInputStream publicKeyIn = new ObjectInputStream(new FileInputStream(publicKeyFile))) {
                publicKey = (PublicKey) publicKeyIn.readObject();
            }
            
            PrivateKey privateKey;
            try (ObjectInputStream privateKeyIn = new ObjectInputStream(new FileInputStream(privateKeyFile))) {
                privateKey = (PrivateKey) privateKeyIn.readObject();
            }
            
            serverKeyPair = new KeyPair(publicKey, privateKey);
            System.out.println("Llaves RSA cargadas correctamente");
        } else {
            // Generar nuevas llaves
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEY_SIZE_RSA);
            serverKeyPair = keyGen.generateKeyPair();
            
            try ( // Guardar llaves
                    ObjectOutputStream publicKeyOut = new ObjectOutputStream(new FileOutputStream(publicKeyFile))) {
                publicKeyOut.writeObject(serverKeyPair.getPublic());
            }
            
            try (ObjectOutputStream privateKeyOut = new ObjectOutputStream(new FileOutputStream(privateKeyFile))) {
                privateKeyOut.writeObject(serverKeyPair.getPrivate());
            }
            
            System.out.println("Nuevas llaves RSA generadas y guardadas");
        }
    }
    
    
}