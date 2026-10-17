
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) {

        try {
            // Load IDS configuration.
            IDSConfig config =
                    new IDSConfig("config/ids.properties");

            // Default network event file.
            String filename = "data/network_events.csv";

            if (args.length > 0) {
                filename = args[0];
            }

            // Read network events.
            List<NetworkEvent> events =
                    TrafficReader.readEvents(filename);

            System.out.println("Java Intrusion Detection System");
            System.out.println("-------------------------------");
            System.out.println("Total events: " + events.size());

            for (NetworkEvent event : events) {

                System.out.println(
                        event.getTimestamp() + " | " +
                        event.getSourceIP() + " -> " +
                        event.getDestinationIP() + " | Port: " +
                        event.getDestinationPort() + " | Type: " +
                        event.getEventType() + " | Bytes: " +
                        event.getBytes()
                );
            }

            // Brute-force detection.
            System.out.println();
            System.out.println("=== Security Alerts ===");

            List<SecurityAlert> alerts = BruteForceDetector.detect(
                    events,
                    config.getPositiveInt("bruteforce.threshold"),
                    config.getPositiveLong("bruteforce.windowSeconds")
            );

            if (alerts.isEmpty()) {
                System.out.println(
                        "No suspicious login activity detected."
                );
            } else {
                for (SecurityAlert alert : alerts) {
                    System.out.println(alert);
                }
            }

            // Port-scan detection.
            System.out.println();
            System.out.println("=== Port Scan Alerts ===");

            List<SecurityAlert> portScanAlerts = PortScanDetector.detect(
                    events,
                    config.getPositiveInt("portscan.threshold"),
                    config.getPositiveLong("portscan.windowSeconds")
            );

            if (portScanAlerts.isEmpty()) {
                System.out.println(
                        "No port scanning activity detected."
                );
            } else {
                for (SecurityAlert alert : portScanAlerts) {
                    System.out.println(alert);
                }
            }

            // Traffic-volume detection.
            System.out.println();
            System.out.println("=== Traffic Volume Alerts ===");

            List<SecurityAlert> volumeAlerts =
                    TrafficVolumeDetector.detect(
                            events,
                            config.getPositiveLong("traffic.bytesThreshold")
                    );

            if (volumeAlerts.isEmpty()) {
                System.out.println(
                        "No high-volume events detected."
                );
            } else {
                for (SecurityAlert alert : volumeAlerts) {
                    System.out.println(alert);
                }
            }

            // Combine alerts from all detectors.
            List<SecurityAlert> allAlerts = new ArrayList<>();

            allAlerts.addAll(alerts);
            allAlerts.addAll(portScanAlerts);
            allAlerts.addAll(volumeAlerts);

            // Save structured alerts to CSV.
            AlertLogger.saveAlerts(
                    "output/security_alerts.csv",
                    allAlerts
            );

            System.out.println();
            System.out.println(
                    "Saved " + allAlerts.size() +
                    " alerts to output/security_alerts.csv"
            );
            // Generate and display security statistics.
            SecurityReport.printSummary(events, allAlerts);

        } catch (IOException e) {
            System.err.println(
                    "File error: " + e.getMessage()
            );

        } catch (IllegalArgumentException e) {
            System.err.println(
                    "Configuration error: " + e.getMessage()
            );
        }
    }
}
