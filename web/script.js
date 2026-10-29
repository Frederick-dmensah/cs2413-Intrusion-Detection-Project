
async function loadDashboard() {
    const status = document.getElementById("statusMessage");
    status.textContent = "Loading security data...";

    try {
        
        const dataset =
            document.getElementById("datasetSelect").value;

        const summaryResponse =
            await fetch("/api/summary?dataset=" + dataset);

        const alertsResponse =
            await fetch("/api/alerts?dataset=" + dataset);


        if (!summaryResponse.ok || !alertsResponse.ok) {
            throw new Error("Unable to load IDS data");
        }

        const summary = await summaryResponse.json();
        const alerts = await alertsResponse.json();

        document.getElementById("totalEvents").textContent =
            summary.totalEvents;

        document.getElementById("totalAlerts").textContent =
            summary.totalAlerts;

        document.getElementById("highAlerts").textContent =
            summary.high;

        document.getElementById("mediumAlerts").textContent =
            summary.medium;

        document.getElementById("bruteForce").textContent =
            summary.bruteForce;

        document.getElementById("portScan").textContent =
            summary.portScan;

        document.getElementById("highTraffic").textContent =
            summary.highTraffic;

        const table = document.getElementById("alertsTable");
        table.innerHTML = "";

        for (const alert of alerts) {
            const row = document.createElement("tr");

            const values = [
                alert.timestamp,
                alert.severity,
                alert.attackType,
                alert.sourceIP,
                alert.destinationIP,
                alert.description
            ];

            for (const value of values) {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.appendChild(cell);
            }

            table.appendChild(row);
        }

        if (alerts.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 6;
            cell.textContent = "No security alerts detected.";
            row.appendChild(cell);
            table.appendChild(row);
        }

        status.textContent = "Dashboard updated successfully.";

    } catch (error) {
        status.textContent = "Error: " + error.message;
    }
}

document.getElementById("refreshButton")
    .addEventListener("click", loadDashboard);

loadDashboard();
document.getElementById("datasetSelect")
    .addEventListener("change", loadDashboard);
