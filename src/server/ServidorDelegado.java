import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServidorDelegado implements Runnable {
    private final Socket clientSocket;
    private DataInputStream in;
    private DataOutputStream out;
    
    // Variables para el protocolo
    private BigInteger g, p, serverPrivate, serverPublic, clientPublic, sharedSecret;
    private SecretKey aesKey;
    private SecretKey hmacKey;
    private IvParameterSpec iv;

    public ServidorDelegado(Socket socket) {
        this.clientSocket = socket;
    }
    
    @Override
    public void run() {
        try {
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());
            
            // Iniciar protocolo
            String hello = in.readUTF();
            if (!"HELLO".equals(hello)) {
                throw new Exception("Protocolo incorrecto. No se recibió HELLO");
            }
            
            // Generar y enviar reto
            SecureRandom random = new SecureRandom();
            byte[] retoBytes = new byte[16];
            random.nextBytes(retoBytes);
            String reto = Base64.getEncoder().encodeToString(retoBytes);
            out.writeUTF(reto);
            
            // Calcular y verificar respuesta al reto (Rta=D(K_w-,Reto))
            String respuesta = in.readUTF();
            boolean retoValido = verificarRespuestaReto(reto, respuesta);
            
            if (retoValido) {
                out.writeUTF("OK");
            } else {
                out.writeUTF("ERROR");
                throw new Exception("Verificación de reto fallida");
            }
            
            // Generar parámetros Diffie-Hellman
            long inicioGeneracionDH = System.nanoTime();
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(ServidorPrincipal.getKeySizeDh());
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);
            
            p = dhSpec.getP();
            g = dhSpec.getG();
            
            // Generar llave privada para el servidor
            serverPrivate = new BigInteger(ServidorPrincipal.getKeySizeDh() - 1, random);
            
            // Calcular llave pública del servidor (G^x mod P)
            serverPublic = g.modPow(serverPrivate, p);
            
            // Enviar G, P y llave pública del servidor
            out.writeUTF(g.toString());
            out.writeUTF(p.toString());
            out.writeUTF(serverPublic.toString());
            
            // Firmar (G,P,G^) con llave privada del servidor
            String mensajeDH = g.toString() + "," + p.toString() + "," + serverPublic.toString();
            byte[] firmaDH = firmar(mensajeDH.getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(firmaDH));
            
            // Recibir respuesta de verificación
            String respuestaDH = in.readUTF();
            if (!"OK".equals(respuestaDH)) {
                throw new Exception("Cliente rechazó los parámetros DH");
            }
            
            // Recibir llave pública del cliente
            String clientPublicStr = in.readUTF();
            clientPublic = new BigInteger(clientPublicStr);
            
            // Calcular secreto compartido
            sharedSecret = clientPublic.modPow(serverPrivate, p);
            
            // Generar llaves simétricas a partir del secreto compartido
            generarLlavesDerivadas();
            
            // Enviar IV para el cifrado AES
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);
            iv = new IvParameterSpec(ivBytes);
            out.writeUTF(Base64.getEncoder().encodeToString(ivBytes));
            long finGeneracionDH = System.nanoTime();
            System.out.println("Tiempo generación DH: " + (finGeneracionDH - inicioGeneracionDH) / 1000000.0 + " ms");
            
            // Preparar tabla de servicios para enviar
            StringBuilder tablaStr = new StringBuilder();
            for (String id : ServidorPrincipal.tablaServicios.keySet()) {
                String[] servicioInfo = ServidorPrincipal.tablaServicios.get(id);
                tablaStr.append(id).append(",")
                       .append(servicioInfo[0]).append("\n");
            }
            
            // Cifrar tabla de servicios
            long inicioCifrado = System.nanoTime();
            byte[] tablaCifrada = cifrarAES(tablaStr.toString().getBytes());
            long finCifrado = System.nanoTime();
            System.out.println("Tiempo cifrado simétrico (AES): " + (finCifrado - inicioCifrado) / 1000000.0 + " ms");
            
            // Tiempo de cifrado asimétrico para comparación
            long inicioCifradoRSA = System.nanoTime();
            cifrarRSA(tablaStr.toString().getBytes());
            long finCifradoRSA = System.nanoTime();
            System.out.println("Tiempo cifrado asimétrico (RSA): " + (finCifradoRSA - inicioCifradoRSA) / 1000000.0 + " ms");
            
            // Enviar tabla cifrada
            out.writeUTF(Base64.getEncoder().encodeToString(tablaCifrada));
            
            // Calcular y enviar HMAC de la tabla
            byte[] hmacTabla = calcularHMAC(tablaStr.toString().getBytes());
            out.writeUTF(Base64.getEncoder().encodeToString(hmacTabla));
            
            // Recibir ID del servicio solicitado y dirección IP del cliente
            String mensajeCifrado = in.readUTF();
            String hmacMensaje = in.readUTF();
            
            // Descifrar y verificar HMAC
            byte[] mensajeBytes = Base64.getDecoder().decode(mensajeCifrado);
            byte[] hmacBytes = Base64.getDecoder().decode(hmacMensaje);
            
            long inicioVerificacion = System.nanoTime();
            byte[] mensajeDescifrado = descifrarAES(mensajeBytes);
            boolean hmacValido = verificarHMAC(mensajeDescifrado, hmacBytes);
            long finVerificacion = System.nanoTime();
            System.out.println("Tiempo verificación HMAC: " + (finVerificacion - inicioVerificacion) / 1000000.0 + " ms");
            
            if (!hmacValido) {
                out.writeUTF("ERROR");
                throw new Exception("HMAC inválido en la consulta");
            }
            
            // Procesar solicitud
            String mensajeTexto = new String(mensajeDescifrado);
            String[] partes = mensajeTexto.split(",");
            String idServicio = partes[0];
            String ipCliente = partes[1];
            
            String[] datosServicio;
            if (ServidorPrincipal.tablaServicios.containsKey(idServicio)) {
                datosServicio = ServidorPrincipal.tablaServicios.get(idServicio);
            } else {
                datosServicio = new String[]{"-1", "-1"};
            }
            
            // Construir respuesta: IP y puerto del servidor de servicio
            String respuestaServicio = datosServicio[1] + "," + datosServicio[2];
            
            // Cifrar respuesta
            byte[] respuestaCifrada = cifrarAES(respuestaServicio.getBytes());
            
            // Calcular HMAC de la respuesta
            byte[] hmacRespuesta = calcularHMAC(respuestaServicio.getBytes());
            
            // Enviar respuesta cifrada y HMAC
            out.writeUTF(Base64.getEncoder().encodeToString(respuestaCifrada));
            out.writeUTF(Base64.getEncoder().encodeToString(hmacRespuesta));
            
        } catch (Exception e) {
            System.err.println("Error en delegado: " + e.getMessage());
            //e.printStackTrace();
        } finally {
            try {
                if (in != null) in.close();
                if (out != null) out.close();
                if (clientSocket != null) clientSocket.close();
            } catch (IOException e) {
                //e.printStackTrace();
            }
        }
    }
    
    private boolean verificarRespuestaReto(String reto, String respuesta) throws Exception {
        try {
            // Descifrar la respuesta usando la llave privada del servidor
            byte[] respuestaCifrada = Base64.getDecoder().decode(respuesta);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, ServidorPrincipal.serverKeyPair.getPrivate());
            byte[] respuestaDescifrada = cipher.doFinal(respuestaCifrada);
            
            // Comparar respuesta descifrada con reto original
            return reto.equals(new String(respuestaDescifrada));
        } catch (Exception e) {
            return false;
        }
    }
    
    private byte[] firmar(byte[] datos) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(ServidorPrincipal.serverKeyPair.getPrivate());
        signature.update(datos);
        return signature.sign();
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
    
    private byte[] cifrarRSA(byte[] datos) throws Exception {
        // Usado solo para comparar tiempos
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, ServidorPrincipal.serverKeyPair.getPublic());
        
        // RSA tiene límite en el tamaño de datos a cifrar
        // Solo ciframos un bloque para la comparación
        int blockSize = ServidorPrincipal.getKeySizeDh() / 8 - 11; // Espacio para padding
        if (datos.length > blockSize) {
            byte[] primerBloque = Arrays.copyOfRange(datos, 0, blockSize);
            return cipher.doFinal(primerBloque);
        } else {
            return cipher.doFinal(datos);
        }
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
