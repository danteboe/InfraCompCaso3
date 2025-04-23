import java.util.concurrent.*;

public class ClientePruebaRendimiento {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Uso: java ClientePruebaRendimiento <modo> [num_clientes]");
            System.out.println("Modos disponibles:");
            System.out.println("  - iterativo : Para pruebas con un cliente haciendo 32 consultas secuenciales");
            System.out.println("  - concurrente : Para pruebas con múltiples clientes concurrentes");
            System.out.println("Ejemplo: java ClientePruebaRendimiento concurrente 16");
            return;
        }
        
        String modo = args[0];
        
        try {
            if ("iterativo".equals(modo)) {
                System.out.println("Iniciando prueba con cliente iterativo (32 consultas secuenciales)");
                // Ejecutar cliente en modo automático con 32 consultas
                String[] clienteArgs = {"auto", "32"};
                Cliente.main(clienteArgs);
                
            } else if ("concurrente".equals(modo)) {
                int numClientes = 4; // Valor por defecto
                if (args.length >= 2) {
                    numClientes = Integer.parseInt(args[1]);
                }
                
                System.out.println("Iniciando prueba con " + numClientes + " clientes concurrentes");
                ejecutarClientesConcurrentes(numClientes);
                
            } else {
                System.out.println("Modo no reconocido: " + modo);
            }
            
        } catch (Exception e) {
            System.err.println("Error en ClientePruebaRendimiento: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void ejecutarClientesConcurrentes(int numClientes) throws Exception {
        CountDownLatch latch = new CountDownLatch(numClientes);
        ExecutorService pool = Executors.newFixedThreadPool(numClientes);
        
        long tiempoInicio = System.currentTimeMillis();
        
        // Crear y ejecutar los clientes delegados
        for (int i = 0; i < numClientes; i++) {
            pool.execute(new ClienteDelegado(i + 1, latch));
        }
        
        // Esperar a que todos los clientes terminen
        latch.await();
        
        long tiempoFin = System.currentTimeMillis();
        long tiempoTotal = tiempoFin - tiempoInicio;
        
        System.out.println("\nResultados de la prueba:");
        System.out.println("Número de clientes concurrentes: " + numClientes);
        System.out.println("Tiempo total de ejecución: " + tiempoTotal + " ms");
        System.out.println("Tiempo promedio por cliente: " + (tiempoTotal / numClientes) + " ms");
        
        // Cerrar el pool de hilos
        pool.shutdown();
    }
}