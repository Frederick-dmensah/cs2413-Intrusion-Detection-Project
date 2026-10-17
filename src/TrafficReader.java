
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class TrafficReader {

    public static List<NetworkEvent> readEvents(String filename)
            throws IOException {

        List<NetworkEvent> events = new ArrayList<>();

        try (BufferedReader reader =
                new BufferedReader(new FileReader(filename))) {

            String line;

            while ((line = reader.readLine()) != null) {

                // Remove extra spaces
                line = line.trim();

                // Skip empty lines
                if (line.isEmpty()) {
                    continue;
                }

                // Skip the CSV header
                if (line.toLowerCase().startsWith("timestamp,")) {
                    continue;
                }

                String[] fields = line.split(",", -1);

                if (fields.length != 6) {
                    System.err.println("Invalid row: " + line);
                    continue;
                }

                try {
                    Instant timestamp =
                            Instant.parse(fields[0].trim());

                    String sourceIP = fields[1].trim();
                    String destinationIP = fields[2].trim();

                    int destinationPort =
                            Integer.parseInt(fields[3].trim());

                    String eventType = fields[4].trim();

                    long bytes =
                            Long.parseLong(fields[5].trim());

                    NetworkEvent event = new NetworkEvent(
                            timestamp,
                            sourceIP,
                            destinationIP,
                            destinationPort,
                            eventType,
                            bytes
                    );

                    events.add(event);

                } catch (IllegalArgumentException e) {
                    System.err.println(
                            "Invalid data: " + line
                    );
                }
            }
        }

        return events;
    }
}
