
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

public class BruteForceDetector {

    public static List<SecurityAlert> detect(
            List<NetworkEvent> events,
            int threshold,
            long windowSeconds) {

        List<SecurityAlert> alerts = new ArrayList<>();

        // Store failed login timestamps for each source/destination pair.
        Map<String, Deque<Instant>> failedLogins =
                new HashMap<>();

        // Track pairs already reported during an attack burst.
        Set<String> alertedPairs = new HashSet<>();

        // Sort network events by timestamp.
        List<NetworkEvent> sortedEvents = new ArrayList<>(events);

        sortedEvents.sort(
                Comparator.comparing(NetworkEvent::getTimestamp)
        );

        for (NetworkEvent event : sortedEvents) {

            // Only examine failed login events.
            if (!event.getEventType().equalsIgnoreCase("LOGIN_FAIL")) {
                continue;
            }

            String key = event.getSourceIP() + " -> "
                    + event.getDestinationIP();

            Instant currentTime = event.getTimestamp();

            Deque<Instant> attempts =
                    failedLogins.computeIfAbsent(
                            key, k -> new ArrayDeque<>()
                    );

            // Remove attempts outside the configured time window.
            while (!attempts.isEmpty() &&
                    Duration.between(
                            attempts.peekFirst(),
                            currentTime
                    ).compareTo(Duration.ofSeconds(windowSeconds)) > 0) {

                attempts.removeFirst();
            }

            attempts.addLast(currentTime);

            // Allow a new alert after activity drops below threshold.
            if (attempts.size() < threshold) {
                alertedPairs.remove(key);
            }

            // Generate one structured alert per continuous burst.
            if (attempts.size() >= threshold &&
                    !alertedPairs.contains(key)) {

                SecurityAlert alert = new SecurityAlert(
                        currentTime,
                        "HIGH",
                        "BRUTE_FORCE",
                        event.getSourceIP(),
                        event.getDestinationIP(),
                        attempts.size() +
                                " failed login attempts within " +
                                windowSeconds + " seconds"
                );

                alerts.add(alert);
                alertedPairs.add(key);
            }
        }

        return alerts;
    }
}
