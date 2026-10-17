
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class IDSServer {

    public static void main(String[] args) {

        try {
            // Create a local HTTP server on port 8080.
            HttpServer server = HttpServer.create(
                    new InetSocketAddress("0.0.0.0", 8080), 0
            );

            // Register dashboard routes.
            server.createContext("/", exchange ->
                    serveFile(exchange, "web/index.html", "text/html"));

            server.createContext("/style.css", exchange ->
                    serveFile(exchange, "web/style.css", "text/css"));

            server.createContext("/script.js", exchange ->
                    serveFile(exchange, "web/script.js",
                            "application/javascript"));

            server.setExecutor(null);

            server.start();

            System.out.println("IDS Web Server started.");
            System.out.println(
                    "Open http://localhost:8080 in your browser"
            );

        } catch (IOException e) {
            System.err.println(
                    "Failed to start server: " + e.getMessage()
            );
        }
    }

    private static void serveFile(
            HttpExchange exchange,
            String filename,
            String contentType) throws IOException {

        // Only allow GET requests.
        if (!exchange.getRequestMethod().equals("GET")) {
            sendResponse(exchange, 405,
                    "Method Not Allowed", "text/plain");
            return;
        }

        Path file = Path.of(filename);

        if (!Files.isRegularFile(file)) {
            sendResponse(exchange, 404,
                    "File Not Found", "text/plain");
            return;
        }

        byte[] content = Files.readAllBytes(file);

        exchange.getResponseHeaders().set(
                "Content-Type", contentType + "; charset=UTF-8"
        );

        exchange.sendResponseHeaders(200, content.length);

        try (OutputStream output =
                     exchange.getResponseBody()) {
            output.write(content);
        }
    }

    private static void sendResponse(
            HttpExchange exchange,
            int status,
            String message,
            String contentType) throws IOException {

        byte[] content = message.getBytes(
                StandardCharsets.UTF_8
        );

        exchange.getResponseHeaders().set(
                "Content-Type", contentType + "; charset=UTF-8"
        );

        exchange.sendResponseHeaders(status, content.length);

        try (OutputStream output =
                     exchange.getResponseBody()) {
            output.write(content);
        }
    }
}
