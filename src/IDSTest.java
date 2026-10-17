
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class IDSTest {

    private static int passed = 0;
    private static int failed = 0;

    private static void check(String testName, boolean condition) {

        if (condition) {
            System.out.println("PASS: " + testName);
            passed++;
        } else {
            System.out.println("FAIL: " + testName);
            failed++;
        }
    }

    public static void main(String[] args) {

        // Test 1: Three failed logins within 60 seconds.
        List<NetworkEvent> loginEvents = new ArrayList<>();

        loginEvents.add(new NetworkEvent(
                Instant.parse("2026-10-08T10:00:00Z"),
                "192.168.1.10", "192.168.1.20",
                22, "LOGIN_FAIL", 100
        ));

        loginEvents.add(new NetworkEvent(
                Instant.parse("2026-10-08T10:00:05Z"),
                "192.168.1.10", "192.168.1.20",
                22, "LOGIN_FAIL", 100
        ));

        loginEvents.add(new NetworkEvent(
                Instant.parse("2026-10-08T10:00:10Z"),
                "192.168.1.10", "192.168.1.20",
                22, "LOGIN_FAIL", 100
        ));

        check(
                "Brute-force detection",
                BruteForceDetector.detect(loginEvents, 3, 60).size() == 1
        );

        check(
                "Higher brute-force threshold",
                BruteForceDetector.detect(loginEvents, 4, 60).isEmpty()
        );

        // Test 2: Four distinct destination ports.
        List<NetworkEvent> scanEvents = new ArrayList<>();

        int[] ports = {21, 22, 80, 443};

        for (int i = 0; i < ports.length; i++) {

            scanEvents.add(new NetworkEvent(
                    Instant.parse("2026-10-08T10:01:00Z")
                            .plusSeconds(i * 5),
                    "192.168.1.15",
                    "192.168.1.20",
                    ports[i],
                    "CONNECTION",
                    500
            ));
        }

        check(
                "Port-scan detection",
                PortScanDetector.detect(scanEvents, 4, 60).size() == 1
        );

        check(
                "Higher port-scan threshold",
                PortScanDetector.detect(scanEvents, 5, 60).isEmpty()
        );

        // Test 3: Traffic-volume threshold.
        List<NetworkEvent> trafficEvents = new ArrayList<>();

        trafficEvents.add(new NetworkEvent(
                Instant.parse("2026-10-08T10:02:00Z"),
                "192.168.1.30",
                "192.168.1.20",
                443,
                "TRANSFER",
                15000
        ));

        check(
                "High traffic detection",
                TrafficVolumeDetector.detect(
                        trafficEvents, 10000
                ).size() == 1
        );

        check(
                "Higher traffic threshold",
                TrafficVolumeDetector.detect(
                        trafficEvents, 20000
                ).isEmpty()
        );
        
        // Test 4: Failed logins outside the 60-second window.
        List<NetworkEvent> slowLogins = new ArrayList<>();

        for (int i = 0; i < 3; i++) {
            slowLogins.add(new NetworkEvent(
                    Instant.parse("2026-10-08T12:00:00Z")
                            .plusSeconds(i * 70),
                    "192.168.1.40",
                    "192.168.1.20",
                    22,
                    "LOGIN_FAIL",
                    100
            ));
        }

        check(
                "Brute-force attempts outside time window",
                BruteForceDetector.detect(slowLogins, 3, 60).isEmpty()
        );

        // Test 5: Repeated destination ports should not
        // count as distinct ports.
        List<NetworkEvent> repeatedPorts = new ArrayList<>();

        int[] duplicatePorts = {21, 22, 80, 80};

        for (int i = 0; i < duplicatePorts.length; i++) {
            repeatedPorts.add(new NetworkEvent(
                    Instant.parse("2026-10-08T12:05:00Z")
                            .plusSeconds(i * 5),
                    "192.168.1.50",
                    "192.168.1.20",
                    duplicatePorts[i],
                    "CONNECTION",
                    200
            ));
        }

        check(
                "Repeated ports do not trigger scan",
                PortScanDetector.detect(repeatedPorts, 4, 60).isEmpty()
        );

        // Test 6: Events arriving out of chronological order.
        List<NetworkEvent> unorderedLogins = new ArrayList<>();

        unorderedLogins.add(new NetworkEvent(
                Instant.parse("2026-10-08T13:00:10Z"),
                "192.168.1.60", "192.168.1.20",
                22, "LOGIN_FAIL", 100
        ));

        unorderedLogins.add(new NetworkEvent(
                Instant.parse("2026-10-08T13:00:00Z"),
                "192.168.1.60", "192.168.1.20",
                22, "LOGIN_FAIL", 100
        ));

        unorderedLogins.add(new NetworkEvent(
                Instant.parse("2026-10-08T13:00:05Z"),
                "192.168.1.60", "192.168.1.20",
                22, "LOGIN_FAIL", 100
        ));

        List<SecurityAlert> unorderedAlerts =
                BruteForceDetector.detect(unorderedLogins, 3, 60);

        check(
                "Out-of-order events detected correctly",
                unorderedAlerts.size() == 1 &&
                unorderedAlerts.get(0).getTimestamp().equals(
                        Instant.parse("2026-10-08T13:00:10Z")
                )
        );

        // Test 7: Suppress duplicate brute-force alerts.
        List<NetworkEvent> repeatedLogins = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
            repeatedLogins.add(new NetworkEvent(
                    Instant.parse("2026-10-08T14:00:00Z")
                            .plusSeconds(i * 5),
                    "192.168.1.70", "192.168.1.20",
                    22, "LOGIN_FAIL", 100
            ));
        }

        check(
                "Duplicate brute-force alerts suppressed",
                BruteForceDetector.detect(repeatedLogins, 3, 60).size() == 1
        );

        // Test 8: An event exactly on the traffic threshold.
        List<NetworkEvent> exactTraffic = new ArrayList<>();

        exactTraffic.add(new NetworkEvent(
                Instant.parse("2026-10-08T15:00:00Z"),
                "192.168.1.80", "192.168.1.20",
                443, "TRANSFER", 10000
        ));

        check(
                "Traffic exactly at threshold",
                TrafficVolumeDetector.detect(exactTraffic, 10000).size() == 1
        );

        // Test 9: A login window exactly 60 seconds long.
        List<NetworkEvent> boundaryLogins = new ArrayList<>();

        int[] offsets = {0, 30, 60};

        for (int offset : offsets) {
            boundaryLogins.add(new NetworkEvent(
                    Instant.parse("2026-10-08T16:00:00Z")
                            .plusSeconds(offset),
                    "192.168.1.90", "192.168.1.20",
                    22, "LOGIN_FAIL", 100
            ));
        }

        check(
                "Brute-force at exact time boundary",
                BruteForceDetector.detect(boundaryLogins, 3, 60).size() == 1
        );

        // Display final test results.
        System.out.println();
        System.out.println("========== TEST RESULTS ==========");
        System.out.println("Passed: " + passed);
        System.out.println("Failed: " + failed);
        System.out.println("==================================");

        if (failed > 0) {
            System.exit(1);
        }
    }
}

