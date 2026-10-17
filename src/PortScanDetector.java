
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PortScanDetector {

    public static List<SecurityAlert> detect(
            List<NetworkEvent> events,
            int portThreshold,
            long windowSeconds) {

        List<SecurityAlert> alerts = new ArrayList<>();

        // Store recent connection events for each source/destination pair.
        Map<String, Deque<NetworkEvent>> connections =
                new HashMap<>();

        // Avoid duplicate alerts during the same scan burst.
        Set<String> alertedPairs = new HashSet<>();

        // Sort events chronologically.
        List<NetworkEvent> sortedEvents = new ArrayList<>(events);

        sortedEvents.sort(
                Comparator.comparing(NetworkEvent::getTimestamp)
        );

        for (NetworkEvent event : sortedEvents) {

            if (!event.getEventType().equalsIgnoreCase("CONNECTION")) {
                continue;
            }

            String key = event.getSourceIP() + " -> "
                    + event.getDestinationIP();

            Instant currentTime = event.getTimestamp();

            Deque<NetworkEvent> recent =
                    connections.computeIfAbsent(
                            key, k -> new ArrayDeque<>()
                    );

            // Remove connections outside the configured window.
            while (!recent.isEmpty() &&
                    Duration.between(
                            recent.peekFirst().getTimestamp(),
                            currentTime
                    ).compareTo(Duration.ofSeconds(windowSeconds)) > 0) {

                recent.removeFirst();
            }

            // Record current connection.
            recent.addLast(event);

            // Count distinct destination ports.
            Set<Integer> uniquePorts = new HashSet<>();

            for (NetworkEvent connection : recent) {
                uniquePorts.add(connection.getDestinationPort());
            }

            // Reset alert status if activity drops below threshold.
            if (uniquePorts.size() < portThreshold) {
                alertedPairs.remove(key);
            }

            // Generate one alert per continuous scan burst.
            if (uniquePorts.size() >= portThreshold &&
                    !alertedPairs.contains(key)) {

                SecurityAlert alert = new SecurityAlert(
                        currentTime,
                        "MEDIUM",
                        "PORT_SCAN",
                        event.getSourceIP(),
                        event.getDestinationIP(),
                        uniquePorts.size() +
                                " unique destination ports within " +
                                windowSeconds + " seconds"
                );

                alerts.add(alert);
                alertedPairs.add(key);
            }
        }

        return alerts;
    }
}
