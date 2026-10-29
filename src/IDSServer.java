
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
            
        server.createContext("/api/alerts", exchange -> {

        if (!exchange.getRequestMethod().equals("GET")) {
                sendResponse(exchange, 405,
                        "Method Not Allowed", "text/plain");
                return;
        }

    try {
        String filename = getDatasetFile(exchange);

        if (filename == null) {
        sendResponse(exchange, 400,
                "Invalid dataset", "text/plain");
        return;
        }

        java.util.List<SecurityAlert> alerts =
                IDSAnalyzer.analyze(filename);

        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < alerts.size(); i++) {
            SecurityAlert alert = alerts.get(i);

            if (i > 0) {
                json.append(",");
            }

            json.append("{")
                .append("\"timestamp\":\"")
                .append(escapeJson(alert.getTimestamp().toString()))
                .append("\",\"severity\":\"")
                .append(escapeJson(alert.getSeverity()))
                .append("\",\"attackType\":\"")
                .append(escapeJson(alert.getAttackType()))
                .append("\",\"sourceIP\":\"")
                .append(escapeJson(alert.getSourceIP()))
                .append("\",\"destinationIP\":\"")
                .append(escapeJson(alert.getDestinationIP()))
                .append("\",\"description\":\"")
                .append(escapeJson(alert.getDescription()))
                .append("\"}");
        }

        json.append("]");

        sendResponse(exchange, 200,
                json.toString(), "application/json");

    } catch (IOException | IllegalArgumentException e) {
        sendResponse(exchange, 500,
                "Unable to analyze IDS data",
                "text/plain");
        System.err.println(e.getMessage());
    }
});
  
        server.createContext("/api/summary", exchange -> {

        if (!exchange.getRequestMethod().equals("GET")) {
                sendResponse(exchange, 405,
                        "Method Not Allowed", "text/plain");
                return;
        }

    try {
        String filename = getDatasetFile(exchange);

        if (filename == null) {
        sendResponse(exchange, 400,
                "Invalid dataset", "text/plain");
        return;
        }
        java.util.List<NetworkEvent> events =
                TrafficReader.readEvents(filename);

        java.util.List<SecurityAlert> alerts =
                IDSAnalyzer.analyze(filename);

        int high = 0;
        int medium = 0;
        int low = 0;

        int bruteForce = 0;
        int portScan = 0;
        int highTraffic = 0;

        for (SecurityAlert alert : alerts) {

            if (alert.getSeverity().equals("HIGH")) {
                high++;
            } else if (alert.getSeverity().equals("MEDIUM")) {
                medium++;
            } else if (alert.getSeverity().equals("LOW")) {
                low++;
            }

            if (alert.getAttackType().equals("BRUTE_FORCE")) {
                bruteForce++;
            } else if (alert.getAttackType().equals("PORT_SCAN")) {
                portScan++;
            } else if (alert.getAttackType().equals("HIGH_TRAFFIC")) {
                highTraffic++;
            }
        }

        String json = "{"
                + "\"totalEvents\":" + events.size() + ","
                + "\"totalAlerts\":" + alerts.size() + ","
                + "\"high\":" + high + ","
                + "\"medium\":" + medium + ","
                + "\"low\":" + low + ","
                + "\"bruteForce\":" + bruteForce + ","
                + "\"portScan\":" + portScan + ","
                + "\"highTraffic\":" + highTraffic
                + "}";

        sendResponse(exchange, 200,
                json, "application/json");

        } catch (IOException | IllegalArgumentException e) {
                System.err.println(e.getMessage());
                sendResponse(exchange, 500,
                        "Unable to generate IDS summary",
                        "text/plain");
                 }
        });



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

        private static String escapeJson(String value) {
            if (value == null) {
                 return "";
            }

                  return value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
        }
       
        private static String getDatasetFile(HttpExchange exchange) {

                String query = exchange.getRequestURI().getRawQuery();

                if (query == null) {
                        return "data/realistic_events.csv";
                }

                if (query.equals("dataset=normal")) {
                        return "data/normal_events.csv";
                }

                if (query.equals("dataset=malicious")) {
                        return "data/network_events.csv";
                }

                if (query.equals("dataset=realistic")) {
                        return "data/realistic_events.csv";
                }

                return null;
        }


}
