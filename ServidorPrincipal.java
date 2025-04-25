import java.io.*;
import java.net.*;
import java.security.*;
import java.util.HashMap;

public class ServidorPrincipal {
    private static final int PUERTO = 8888;
    private static final String KEY_FILE_PUBLIC = "server_public.key";
    private static final String KEY_FILE_PRIVATE = "server_private.key";

    public static HashMap<String, String[]> tablaServicios = new HashMap<>();
    public static KeyPair serverKeyPair;

    private static final int KEY_SIZE_RSA = 1024;
    private static final int KEY_SIZE_DH = 1024;
    private static final int KEY_SIZE_AES = 256;

    public static void main(String[] args) {
        try {
            inicializarTablaServicios();
            cargarOGenerarLlaves();
            //el backlog de 100 hizo que el server no exoplote
            //básicamente es el número de conexiones que puede aceptar el servidor antes de rechazar nuevas conexiones 
            try (ServerSocket serverSocket = new ServerSocket(PUERTO, 100)) {
                System.out.println("Servidor principal iniciado en el puerto " + PUERTO);
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    System.out.println("Nuevo cliente conectado desde " + clientSocket.getInetAddress().getHostAddress());

                    Thread clienteThread = new Thread(() -> {
                        try {
                            new ServidorDelegado(clientSocket).run();
                        } catch (Exception e) {
                            System.err.println("Error en hilo de cliente: " + e.getMessage());
                            //pasé como dos horas fixeando esto porque los hilos seguían consumiendo recursos
                        } finally {
                            try {
                                clientSocket.close();
                            } catch (IOException e) {
                                System.err.println("Error cerrando socket cliente: " + e.getMessage());
                            }
                            System.out.println("Cliente desconectado y recurso liberado");
                        }
                    });

                    clienteThread.start();
                }
            } catch (Exception e) {
                System.err.println("Error en servidor principal (socket): " + e.getMessage());
            }

        } catch (Exception e) {
            System.err.println("Error general en servidor principal: " + e.getMessage());
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
            try (ObjectInputStream publicKeyIn = new ObjectInputStream(new FileInputStream(publicKeyFile));
                 ObjectInputStream privateKeyIn = new ObjectInputStream(new FileInputStream(privateKeyFile))) {
                PublicKey publicKey = (PublicKey) publicKeyIn.readObject();
                PrivateKey privateKey = (PrivateKey) privateKeyIn.readObject();
                serverKeyPair = new KeyPair(publicKey, privateKey);
                System.out.println("Llaves RSA cargadas correctamente");
            }
        } else {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(KEY_SIZE_RSA);
            serverKeyPair = keyGen.generateKeyPair();

            try (ObjectOutputStream publicKeyOut = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
                 ObjectOutputStream privateKeyOut = new ObjectOutputStream(new FileOutputStream(privateKeyFile))) {
                publicKeyOut.writeObject(serverKeyPair.getPublic());
                privateKeyOut.writeObject(serverKeyPair.getPrivate());
            }

            System.out.println("Nuevas llaves RSA generadas y guardadas");
        }
    }
}
