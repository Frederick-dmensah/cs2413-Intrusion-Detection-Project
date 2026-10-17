
import java.util.ArrayList;
import java.util.List;

public class TrafficVolumeDetector {

    public static List<SecurityAlert> detect(
            List<NetworkEvent> events,
            long byteThreshold) {

        List<SecurityAlert> alerts = new ArrayList<>();

        for (NetworkEvent event : events) {

            // Detect individual events exceeding the byte threshold.
            if (event.getBytes() >= byteThreshold) {

                SecurityAlert alert = new SecurityAlert(
                        event.getTimestamp(),
                        "HIGH",
                        "HIGH_TRAFFIC",
                        event.getSourceIP(),
                        event.getDestinationIP(),
                        "Traffic event containing " +
                                event.getBytes() + " bytes"
                );

                alerts.add(alert);
            }
        }

        return alerts;
    }
}
