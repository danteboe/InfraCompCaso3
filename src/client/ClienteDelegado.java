import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ClienteDelegado implements Runnable {
    private static final String SERVIDOR_HOST = "localhost";
    private static final int SERVIDOR_PUERTO = 8888;
    private static final String KEY_FILE_PUBLIC = "server_public.key";
    
    // Variables para la comunicación
    private PublicKey serverPublicKey;
    private BigInteger g, p, clientPrivate, clientPublic, serverPublic, sharedSecret;
    private SecretKey aesKey;
    private SecretKey hmacKey;
    private IvParameterSpec iv;
    private final CountDownLatch latch;
    private final int id;
    
    public ClienteDelegado(int id, CountDownLatch latch) {
        this.id = id;
        this.latch = latch;
    }
    
    @Override
    public void run() {
        Socket socket = null;
        DataInputStream in = null;
        DataOutputStream out = null;
        
        try {
            // Cargar llave pública del servidor
            cargarLlavePublica();
            
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
                System.out.println("Cliente " + id + ": Error en la consulta - HMAC inválido");
                return;
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
                System.out.println("Cliente " + id + ": Consulta completada exitosamente");
            } else {
                System.out.println("Cliente " + id + ": Error en la respuesta - HMAC inválido");
            }
            
        } catch (Exception e) {
            System.err.println("Error en cliente delegado " + id + ": " + e.getMessage());
            //e.printStackTrace();
        } finally {
            try {
                if (in != null) in.close();
                if (out != null) out.close();
                if (socket != null) socket.close();
            } catch (IOException e) {
                //e.printStackTrace();
            }
            latch.countDown();
        }
    }
    
    private void cargarLlavePublica() throws Exception {
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(KEY_FILE_PUBLIC))) {
            serverPublicKey = (PublicKey) keyIn.readObject();
        }
    }
    
    private void establecerComunicacionSegura(DataInputStream in, DataOutputStream out) throws Exception {
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
    
    private void generarLlavesDerivadas() throws Exception {
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
    
    private byte[] cifrarAES(byte[] datos) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        return cipher.doFinal(datos);
    }
    
    private byte[] descifrarAES(byte[] datosCifrados) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
        return cipher.doFinal(datosCifrados);
    }
    
    private byte[] calcularHMAC(byte[] datos) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(datos);
    }
    
    private boolean verificarHMAC(byte[] datos, byte[] hmacRecibido) throws Exception {
        byte[] hmacCalculado = calcularHMAC(datos);
        return MessageDigest.isEqual(hmacCalculado, hmacRecibido);
    }
}