
import java.time.Instant;

public class SecurityAlert {

    private final Instant timestamp;
    private final String severity;
    private final String attackType;
    private final String sourceIP;
    private final String destinationIP;
    private final String description;

    // Constructor
    public SecurityAlert(
            Instant timestamp,
            String severity,
            String attackType,
            String sourceIP,
            String destinationIP,
            String description) {

        this.timestamp = timestamp;
        this.severity = severity;
        this.attackType = attackType;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.description = description;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSeverity() {
        return severity;
    }

    public String getAttackType() {
        return attackType;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public String getDescription() {
        return description;
    }

    // Format the alert for terminal output.
    @Override
    public String toString() {
        return "[" + severity + "] " +
                attackType +
                " | Source: " + sourceIP +
                " | Destination: " + destinationIP +
                " | " + description +
                " | Time: " + timestamp;
    }
}
