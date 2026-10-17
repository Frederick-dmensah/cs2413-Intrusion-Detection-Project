
import java.time.Instant;

public class NetworkEvent {

    private Instant timestamp;
    private String sourceIP;
    private String destinationIP;
    private int destinationPort;
    private String eventType;
    private long bytes;

    public NetworkEvent(Instant timestamp, String sourceIP,
                        String destinationIP, int destinationPort,
                        String eventType, long bytes) {

        this.timestamp = timestamp;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.destinationPort = destinationPort;
        this.eventType = eventType;
        this.bytes = bytes;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public int getDestinationPort() {
        return destinationPort;
    }

    public String getEventType() {
        return eventType;
    }

    public long getBytes() {
        return bytes;
    }
}
