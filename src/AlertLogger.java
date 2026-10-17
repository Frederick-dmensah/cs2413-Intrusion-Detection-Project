
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class AlertLogger {

    // Escape values that contain commas, quotes, or newlines.
    private static String escapeCSV(String value) {

        if (value == null) {
            return "";
        }

        String escaped = value.replace("\"", "\"\"");

        if (escaped.contains(",") ||
                escaped.contains("\"") ||
                escaped.contains("\n") ||
                escaped.contains("\r")) {

            return "\"" + escaped + "\"";
        }

        return escaped;
    }

    public static void saveAlerts(
            String filename,
            List<SecurityAlert> alerts) throws IOException {

        try (BufferedWriter writer =
                     new BufferedWriter(new FileWriter(filename))) {

            // Write CSV header.
            writer.write(
                    "timestamp,severity,attackType," +
                    "sourceIP,destinationIP,description"
            );
            writer.newLine();

            // Write each structured alert.
            for (SecurityAlert alert : alerts) {

                writer.write(
                        escapeCSV(alert.getTimestamp().toString()) + "," +
                        escapeCSV(alert.getSeverity()) + "," +
                        escapeCSV(alert.getAttackType()) + "," +
                        escapeCSV(alert.getSourceIP()) + "," +
                        escapeCSV(alert.getDestinationIP()) + "," +
                        escapeCSV(alert.getDescription())
                );

                writer.newLine();
            }
        }
    }
}
