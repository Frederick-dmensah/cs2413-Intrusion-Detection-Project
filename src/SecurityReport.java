
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class SecurityReport {

    public static void printSummary(
            List<NetworkEvent> events,
            List<SecurityAlert> alerts) {

        // Count alerts by severity.
        Map<String, Integer> severityCounts = new HashMap<>();

        // Count alerts by attack type.
        Map<String, Integer> attackCounts = new HashMap<>();

        for (SecurityAlert alert : alerts) {

            String severity = alert.getSeverity();
            String attackType = alert.getAttackType();

            severityCounts.put(
                    severity,
                    severityCounts.getOrDefault(severity, 0) + 1
            );

            attackCounts.put(
                    attackType,
                    attackCounts.getOrDefault(attackType, 0) + 1
            );
        }

        System.out.println();
        System.out.println("========== IDS SECURITY SUMMARY ==========");
        System.out.println();

        System.out.println("Total Network Events: " + events.size());
        System.out.println("Total Security Alerts: " + alerts.size());

        System.out.println();
        System.out.println("Alerts by Severity:");

        System.out.println("HIGH:     " +
                severityCounts.getOrDefault("HIGH", 0));

        System.out.println("MEDIUM:   " +
                severityCounts.getOrDefault("MEDIUM", 0));

        System.out.println("LOW:      " +
                severityCounts.getOrDefault("LOW", 0));

        System.out.println("CRITICAL: " +
                severityCounts.getOrDefault("CRITICAL", 0));

        System.out.println();
        System.out.println("Alerts by Attack Type:");

        System.out.println("BRUTE_FORCE:  " +
                attackCounts.getOrDefault("BRUTE_FORCE", 0));

        System.out.println("PORT_SCAN:    " +
                attackCounts.getOrDefault("PORT_SCAN", 0));

        System.out.println("HIGH_TRAFFIC: " +
                attackCounts.getOrDefault("HIGH_TRAFFIC", 0));

        System.out.println();
        System.out.println("==========================================");
    }
}

