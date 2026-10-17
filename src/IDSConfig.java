
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class IDSConfig {

    private final Properties properties = new Properties();

    public IDSConfig(String filename) throws IOException {
        try (FileInputStream input = new FileInputStream(filename)) {
            properties.load(input);
        }
    }

    public int getPositiveInt(String key) {
        String value = properties.getProperty(key);

        if (value == null) {
            throw new IllegalArgumentException(
                "Missing configuration: " + key
            );
        }

        try {
            int number = Integer.parseInt(value.trim());

            if (number <= 0) {
                throw new IllegalArgumentException(
                    "Configuration must be positive: " + key
                );
            }

            return number;

        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                "Invalid integer for " + key + ": " + value,
                e
            );
        }
    }

    public long getPositiveLong(String key) {
        String value = properties.getProperty(key);

        if (value == null) {
            throw new IllegalArgumentException(
                "Missing configuration: " + key
            );
        }

        try {
            long number = Long.parseLong(value.trim());

            if (number <= 0) {
                throw new IllegalArgumentException(
                    "Configuration must be positive: " + key
                );
            }

            return number;

        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                "Invalid number for " + key + ": " + value,
                e
            );
        }
    }
}

