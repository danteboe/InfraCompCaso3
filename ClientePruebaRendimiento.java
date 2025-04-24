import java.util.concurrent.CyclicBarrier;

public class ClientePruebaRendimiento {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Uso: java ClientePruebaRendimiento <modo> [parametro]");
            System.out.println("Modos disponibles:");
            System.out.println("  - iterativo <n>   : Un cliente hace n consultas secuenciales");
            System.out.println("  - concurrente <n> : n clientes hacen consultas concurrentemente");
            System.out.println("Ejemplo: java ClientePruebaRendimiento iterativo 50");
            return;
        }

        String modo = args[0];

        try {
            if (null == modo) {
                System.out.println("Modo no reconocido: " + modo);
            } else switch (modo) {
                case "iterativo" -> {
                    int numIteraciones = 32; // Valor por defecto si no se da otro. aasí no explota el programa
                    if (args.length >= 2) {
                        numIteraciones = Integer.parseInt(args[1]);
                    }   System.out.println("Iniciando prueba con cliente iterativo (" + numIteraciones + " consultas secuenciales)");
                    // lama internamente a Cliente con el modo iterativo "auto"
                    String[] clienteArgs = {"auto", String.valueOf(numIteraciones)};
                    Cliente.main(clienteArgs);
                }
                case "concurrente" -> {
                    int numClientes = 4; //valor por defecto para que el programa no explote
                    if (args.length >= 2) {
                        numClientes = Integer.parseInt(args[1]);
                    }   System.out.println("Iniciando prueba con " + numClientes + " clientes concurrentes");
                    ejecutarClientesConcurrentes(numClientes);
                }
                default -> System.out.println("Modo no reconocido: " + modo);
            }

        } catch (Exception e) {
            System.err.println("Error en ClientePruebaRendimiento: " + e.getMessage());
            //e.printStackTrace();
        }
    }

    private static void ejecutarClientesConcurrentes(int numClientes) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(numClientes); // sincroniza inicio
        Thread[] threads = new Thread[numClientes];
    
        long tiempoInicio = System.currentTimeMillis();
    
        for (int i = 0; i < numClientes; i++) {
            threads[i] = new Thread(new ClienteDelegado(i + 1, barrier));
            threads[i].start();
        }
    
        for (int i = 0; i < numClientes; i++) {
            threads[i].join(); // espera a que terminen todos
        }
    
        long tiempoFin = System.currentTimeMillis();
        long tiempoTotal = tiempoFin - tiempoInicio;
    
        System.out.println("\nResultados de la prueba:");
        System.out.println("Número de clientes concurrentes: " + numClientes);
        System.out.println("Tiempo total de ejecución: " + tiempoTotal + " ms");
        System.out.println("Tiempo promedio por cliente: " + (tiempoTotal / numClientes) + " ms");
    }
    
}
