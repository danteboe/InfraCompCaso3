import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Cliente {
    private static final String SERVIDOR_HOST = "localhost";
    private static final int SERVIDOR_PUERTO = 8888;
    private static final String KEY_FILE_PUBLIC = "server_public.key";
    
    // Variables para la generación de llaves
    private static PublicKey serverPublicKey;
    private static BigInteger g, p, clientPrivate, clientPublic, serverPublic, sharedSecret;
    private static SecretKey aesKey;
    private static SecretKey hmacKey;
    private static IvParameterSpec iv;
    
    public static void main(String[] args) {
        try {
            // Cargar llave pública del servidor
            cargarLlavePublica();
            
            // Modo de ejecución: interactivo o automático
            if (args.length > 0 && args[0].equals("auto")) {
                int numConsultas = 32;
                if (args.length > 1) {
                    numConsultas = Integer.parseInt(args[1]);
                }
                modoAutomatico(numConsultas);
            } else {
                modoInteractivo();
            }
            
        } catch (Exception e) {
            System.err.println("Error en cliente: " + e.getMessage());
            //e.printStackTrace();
        }
    }
    
    private static void cargarLlavePublica() throws Exception {
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(KEY_FILE_PUBLIC))) {
            serverPublicKey = (PublicKey) keyIn.readObject();
        }
        System.out.println("Llave pública del servidor cargada correctamente");
    }
    
    private static void modoInteractivo() throws Exception {
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;
        
        try {
            socket = new Socket(SERVIDOR_HOST, SERVIDOR_PUERTO);
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            try (Scanner scanner = new Scanner(System.in)) {
                // Iniciar protocolo
                System.out.println("Conectando con el servidor principal...");
                establecerComunicacionSegura(in, out);
            
            // Recibir tabla de servicios cifrada
            String tablaCifradaStr = in.readUTF();
            String hmacTablaStr = in.readUTF();
            
            byte[] tablaCifrada = Base64.getDecoder().decode(tablaCifradaStr);
            byte[] hmacTabla = Base64.getDecoder().decode(hmacTablaStr);
            
            // Verificar HMAC y descifrar tabla
            byte[] tablaBytes = descifrarAES(tablaCifrada);
            boolean hmacValido = verificarHMAC(tablaBytes, hmacTabla);
            
            if (!hmacValido) {
                System.out.println("Error en la consulta: HMAC inválido");
                return;
            }
            
            // Mostrar servicios disponibles
            String tablaStr = new String(tablaBytes);
            System.out.println("\nServicios disponibles:");
            System.out.println("ID\tServicio");
            System.out.println("-----------------");
            
            String[] lineas = tablaStr.split("\n");
            for (String linea : lineas) {
                System.out.println(linea.replace(",", "\t"));
            }
            
            // Solicitar servicio al usuario
            System.out.print("\nIngrese el ID del servicio deseado: ");
            String idServicio = scanner.nextLine().trim();
            
            // Preparar mensaje con ID de servicio y dirección IP del cliente
            String ipCliente = socket.getLocalAddress().getHostAddress();
            String mensaje = idServicio + "," + ipCliente;
            
            // Cifrar mensaje y calcular HMAC
            byte[] mensajeCifrado = cifrarAES(mensaje.getBytes());
            byte[] hmacMensaje = calcularHMAC(mensaje.getBytes());
            
            // Enviar solicitud cifrada
            out.writeUTF(Base64.getEncoder().encodeToString(mensajeCifrado));
            out.writeUTF(Base64.getEncoder().encodeToString(hmacMensaje));
            
            // Recibir respuesta del servidor
            String respuestaCifradaStr = in.readUTF();
            String hmacRespuestaStr = in.readUTF();
            
            byte[] respuestaCifrada = Base64.getDecoder().decode(respuestaCifradaStr);
            byte[] hmacRespuesta = Base64.getDecoder().decode(hmacRespuestaStr);
            
            // Verificar HMAC y descifrar respuesta
            byte[] respuestaBytes = descifrarAES(respuestaCifrada);
            boolean hmacRespuestaValido = verificarHMAC(respuestaBytes, hmacRespuesta);
            
            if (!hmacRespuestaValido) {
                System.out.println("Error en la respuesta: HMAC inválido");
                return;
            }
            
            // Mostrar respuesta del servidor
                // Mostrar respuesta del servidor
                String respuesta = new String(respuestaBytes);
                String[] partesRespuesta = respuesta.split(",");
                
                if ("-1".equals(partesRespuesta[0])) {
                    System.out.println("\nEl servicio solicitado no existe");
                } else {
                    System.out.println("\nDirección del servidor de servicio:");
                    System.out.println("IP: " + partesRespuesta[0]);
                    System.out.println("Puerto: " + partesRespuesta[1]);
                }
            }
        } finally {
            // Cerrar recursos
            if (in != null) in.close();
            if (out != null) out.close();
            if (socket != null) socket.close();
        }
    }
    
    private static void modoAutomatico(int numConsultas) throws Exception {
        System.out.println("Modo automático: realizando " + numConsultas + " consultas secuenciales");
        
        for (int i = 0; i < numConsultas; i++) {
            Socket socket = null;
            DataInputStream in = null;
            DataOutputStream out = null;
            
            try {
                socket = new Socket(SERVIDOR_HOST, SERVIDOR_PUERTO);
                in = new DataInputStream(socket.getInputStream());
                out = new DataOutputStream(socket.getOutputStream());
                
                // Establecer comunicación segura
                establecerComunicacionSegura(in, out);
                
                // Recibir tabla de servicios
                String tablaCifradaStr = in.readUTF();
                String hmacTablaStr = in.readUTF();
                
                byte[] tablaCifrada = Base64.getDecoder().decode(tablaCifradaStr);
                byte[] hmacTabla = Base64.getDecoder().decode(hmacTablaStr);
                
                // Verificar y descifrar tabla
                byte[] tablaBytes = descifrarAES(tablaCifrada);
                boolean hmacValido = verificarHMAC(tablaBytes, hmacTabla);
                
                if (!hmacValido) {
                    System.out.println("Consulta " + (i+1) + ": Error en la consulta");
                    continue;
                }
                
                // Seleccionar un servicio aleatorio
                String[] servicios = {"S1", "S2", "S3"};
                int indiceAleatorio = new SecureRandom().nextInt(servicios.length);
                String idServicio = servicios[indiceAleatorio];
                
                // Preparar mensaje
                String ipCliente = socket.getLocalAddress().getHostAddress();
                String mensaje = idServicio + "," + ipCliente;
                
                // Cifrar y calcular HMAC
                byte[] mensajeCifrado = cifrarAES(mensaje.getBytes());
                byte[] hmacMensaje = calcularHMAC(mensaje.getBytes());
                
                // Enviar solicitud
                out.writeUTF(Base64.getEncoder().encodeToString(mensajeCifrado));
                out.writeUTF(Base64.getEncoder().encodeToString(hmacMensaje));
                
                // Recibir respuesta
                String respuestaCifradaStr = in.readUTF();
                String hmacRespuestaStr = in.readUTF();
                
                // Verificar respuesta
                byte[] respuestaCifrada = Base64.getDecoder().decode(respuestaCifradaStr);
                byte[] hmacRespuesta = Base64.getDecoder().decode(hmacRespuestaStr);
                
                byte[] respuestaBytes = descifrarAES(respuestaCifrada);
                boolean hmacRespuestaValido = verificarHMAC(respuestaBytes, hmacRespuesta);
                
                if (hmacRespuestaValido) {
                    System.out.println("Consulta " + (i+1) + ": Completada exitosamente");
                } else {
                    System.out.println("Consulta " + (i+1) + ": Error en la respuesta");
                }
                
            } finally {
                if (in != null) in.close();
                if (out != null) out.close();
                if (socket != null) socket.close();
                
                // Pequeña pausa entre consultas
                Thread.sleep(100);
            }
        }
    }
    
    private static void establecerComunicacionSegura(DataInputStream in, DataOutputStream out) throws Exception {
        // Paso 1: Enviar HELLO
        out.writeUTF("HELLO");
        
        // Paso 2: Recibir reto
        String reto = in.readUTF();
        
        // Paso 3: Cifrar reto con llave pública del servidor
        byte[] retoBytes = reto.getBytes();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] retoCifrado = cipher.doFinal(retoBytes);
        
        // Paso 4: Enviar respuesta al reto
        out.writeUTF(Base64.getEncoder().encodeToString(retoCifrado));
        
        // Paso 5: Verificar respuesta del servidor
        String respuestaReto = in.readUTF();
        if (!"OK".equals(respuestaReto)) {
            throw new Exception("Servidor rechazó la autenticación");
        }
        
        // Paso 6: Recibir parámetros DH y firma
        String gStr = in.readUTF();
        String pStr = in.readUTF();
        String serverPublicStr = in.readUTF();
        String firmaStr = in.readUTF();
        
        g = new BigInteger(gStr);
        p = new BigInteger(pStr);
        serverPublic = new BigInteger(serverPublicStr);
        
        // Paso 7: Verificar firma
        String mensajeDH = gStr + "," + pStr + "," + serverPublicStr;
        byte[] firma = Base64.getDecoder().decode(firmaStr);
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(serverPublicKey);
        signature.update(mensajeDH.getBytes());
        
        boolean firmaValida = signature.verify(firma);
        
        // Paso 8: Enviar resultado de verificación
        if (firmaValida) {
            out.writeUTF("OK");
        } else {
            out.writeUTF("ERROR");
            throw new Exception("Firma de parámetros DH inválida");
        }
        
        // Paso 9: Generar llave privada del cliente
        SecureRandom random = new SecureRandom();
        clientPrivate = new BigInteger(1024, random);
        
        // Paso 10: Calcular llave pública del cliente
        clientPublic = g.modPow(clientPrivate, p);
        
        // Paso 11: Enviar llave pública del cliente
        out.writeUTF(clientPublic.toString());
        
        // Paso 12: Calcular secreto compartido
        sharedSecret = serverPublic.modPow(clientPrivate, p);
        
        // Paso 13: Generar llaves simétricas
        generarLlavesDerivadas();
        
        // Paso 14: Recibir IV para AES
        String ivStr = in.readUTF();
        byte[] ivBytes = Base64.getDecoder().decode(ivStr);
        iv = new IvParameterSpec(ivBytes);
    }
    
    private static void generarLlavesDerivadas() throws Exception {
        // Usar SHA-512 para obtener 512 bits de la llave maestra
        MessageDigest sha = MessageDigest.getInstance("SHA-512");
        byte[] sharedSecretBytes = sharedSecret.toByteArray();
        byte[] digest = sha.digest(sharedSecretBytes);
        
        // Dividir el digest en dos mitades
        byte[] aesKeyBytes = Arrays.copyOfRange(digest, 0, 32); // 256 bits para AES
        byte[] hmacKeyBytes = Arrays.copyOfRange(digest, 32, 64); // 256 bits para HMAC
        
        // Crear llaves a partir de los bytes
        aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA256");
    }
    
    private static byte[] cifrarAES(byte[] datos) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        return cipher.doFinal(datos);
    }
    
    private static byte[] descifrarAES(byte[] datosCifrados) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
        return cipher.doFinal(datosCifrados);
    }
    
    private static byte[] calcularHMAC(byte[] datos) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(datos);
    }
    
    private static boolean verificarHMAC(byte[] datos, byte[] hmacRecibido) throws Exception {
        byte[] hmacCalculado = calcularHMAC(datos);
        return MessageDigest.isEqual(hmacCalculado, hmacRecibido);
    }
}