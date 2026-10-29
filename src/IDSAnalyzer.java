
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class IDSAnalyzer {

    public static List<SecurityAlert> analyze(
            String filename) throws IOException {

        IDSConfig config =
                new IDSConfig("config/ids.properties");

        List<NetworkEvent> events =
                TrafficReader.readEvents(filename);

        List<SecurityAlert> allAlerts = new ArrayList<>();

        allAlerts.addAll(BruteForceDetector.detect(
                events,
                config.getPositiveInt("bruteforce.threshold"),
                config.getPositiveLong("bruteforce.windowSeconds")
        ));

        allAlerts.addAll(PortScanDetector.detect(
                events,
                config.getPositiveInt("portscan.threshold"),
                config.getPositiveLong("portscan.windowSeconds")
        ));

        
        allAlerts.addAll(TrafficVolumeDetector.detect(
                events,
                config.getPositiveLong("traffic.bytesThreshold")
        ));

        // Sort alerts by timestamp, earliest first.
        allAlerts.sort((alert1, alert2) ->
                alert1.getTimestamp().compareTo(
                        alert2.getTimestamp()
                )
        );


        return allAlerts;
    }
}
