
import java.util.Scanner;

public class IDSMenu {

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        while (running) {

            System.out.println();
            System.out.println("========== JAVA IDS MENU ==========");
            System.out.println();
            System.out.println("1. Analyze malicious traffic");
            System.out.println("2. Analyze normal traffic");
            System.out.println("3. Analyze realistic traffic");
            System.out.println("4. Analyze a custom CSV file");
            System.out.println("5. Run automated tests");
            System.out.println("0. Exit");
            System.out.println();

            System.out.print("Enter your choice: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {

                case "1":
                    runAnalysis("data/network_events.csv");
                    break;

                case "2":
                    runAnalysis("data/normal_events.csv");
                    break;

                case "3":
                    runAnalysis("data/realistic_events.csv");
                    break;

                case "4":
                    System.out.print("Enter CSV file path: ");
                    String filename = scanner.nextLine().trim();

                    if (filename.isEmpty()) {
                        System.out.println("File path cannot be empty.");
                    } else {
                        runAnalysis(filename);
                    }
                    break;

                case "5":
                    System.out.println();
                    System.out.println("Running IDS automated tests...");
                    IDSTest.main(new String[0]);
                    break;

                case "0":
                    System.out.println("Exiting Java IDS.");
                    running = false;
                    break;

                default:
                    System.out.println(
                            "Invalid choice. Please enter 0 to 5."
                    );
            }
        }

        scanner.close();
    }

    private static void runAnalysis(String filename) {

        System.out.println();
        System.out.println("Analyzing file: " + filename);
        System.out.println();

        Main.main(new String[]{filename});
    }
}

