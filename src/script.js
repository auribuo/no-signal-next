window.onload = () => {
    const button = document.querySelector(".scan-button");
    button.textContent = "Scan"; // Ensure it starts with "Scan"
};

async function scan() {
    try {
        toggleButton();
        const invoke = window.__TAURI__.core.invoke
        const response = await invoke("scan")
        const devices = response.devices;
        //console.log(devices);
        //console.log(response);
        document.getElementById("errorContainer").style.display = "none";
        // Generate list
        generateList(devices);

        // Generate pie chart
        generateVulnChart(devices);
    } catch (error) {
        console.error("Error fetching data:", error);
    }
}

function generateList(devices) {
    const container = document.getElementById("listContainer");
    if (container) {
        container.innerHTML = ""; // Clear existing content

        const flexContainer = document.createElement("div");
        flexContainer.className = "flex-container";

        // Total Devices
        const deviceCountReference = document.getElementById("deviceCount");
        deviceCountReference.innerHTML =
            '<p>Total Devices: <span class="text">' + devices.length + "</span></p>";

        devices.forEach((device) => {
            const card = document.createElement("div");
            card.className = "device-card";

            card.addEventListener("click", () => {
                const details = card.querySelector(".details");
                details.classList.toggle("show");
            });

            const nameBadgeRow = document.createElement("div");
            nameBadgeRow.className = "name-badge-row";

            const deviceName = document.createElement("span");
            deviceName.className = "device-name";
            deviceName.textContent = device.name;

            const deviceIp = document.createElement("span");
            deviceIp.className = "device-ip";
            deviceIp.textContent = device.ip;

            const deviceRiscBadge = document.createElement("span");
            deviceRiscBadge.className = `risk-badge ${getRiscLevelClass(
                device.risk_level
            )}`;
            deviceRiscBadge.textContent = device.risk_level;

            nameBadgeRow.appendChild(deviceName);
            nameBadgeRow.appendChild(deviceIp);
            nameBadgeRow.appendChild(deviceRiscBadge);

            card.appendChild(nameBadgeRow);

            const details = document.createElement("div");
            details.className = "details hidden";

            const vulnList = document.createElement("ul");
            vulnList.className = "vuln-list";

            device.vulnerabilities.forEach((vuln) => {
                console.log(vuln);

                const vulnItem = document.createElement("li");
                vulnItem.className = "vuln-item";

                const vulnName = document.createElement("span");
                vulnName.className = "vuln-name";
                vulnName.textContent = vuln.name;

                // Create a description element
                const vulnDesc = document.createElement("span");
                vulnDesc.className = "vuln-description";
                vulnDesc.textContent = vuln.description || "No description available";

                const vulnRiscBadge = document.createElement("span");
                vulnRiscBadge.className = `risk-badge ${getRiscLevelClass(
                    vuln.risk_level
                )}`;
                vulnRiscBadge.textContent = vuln.risk_level;

                vulnItem.appendChild(vulnName);
                vulnItem.appendChild(vulnDesc); // Append description
                vulnItem.appendChild(vulnRiscBadge);

                vulnList.appendChild(vulnItem);
            });

            details.appendChild(vulnList);
            card.appendChild(details);

            flexContainer.appendChild(card);
        });

        container.appendChild(flexContainer);
    }
}

function getRiscLevelClass(riscLevel) {
    switch (riscLevel) {
        case "High":
            return "high-risk";
        case "Medium":
            return "medium-risk";
        case "Low":
            return "low-risk";
        default:
            return "";
    }
}

function toggleButton() {
    const button = document.querySelector(".scan-button");
    const titleContainer = document.getElementById("titleContainer");
    const resultContainer = document.getElementById("resultContainer");
    const currentText = button.textContent;

    if (currentText === "Scan") {
        button.textContent = "Back";
        titleContainer.style.display = "none";
        resultContainer.style.display = "flex";
    } else {
        button.textContent = "Scan";
        titleContainer.style.display = "block";
        resultContainer.style.display = "none";
    }
}

function generateVulnChart(devices) {
    const riskCounts = { High: 0, Medium: 0, Low: 0 };

    devices.forEach((device) => {
        device.vulnerabilities.forEach((vuln) => {
            riskCounts[vuln.risk_level]++;
        });
    });

    const ctx = document.getElementById("vulnChart").getContext("2d");
    document.getElementById("riskLow").innerHTML = riskCounts.Low;
    document.getElementById("riskMedium").innerHTML = riskCounts.Medium;
    document.getElementById("riskHigh").innerHTML = riskCounts.High;

    new Chart(ctx, {
        type: "pie",
        data: {
            labels: [
                "High Risk: " + riskCounts.High,
                "Medium Risk: " + riskCounts.Medium,
                "Low Risk: " + riskCounts.Low,
            ],
            datasets: [
                {
                    label: "Vulnerabilities by Risk Level",
                    data: [riskCounts.High, riskCounts.Medium, riskCounts.Low],
                    backgroundColor: ["#e74c3c", "#f39c12", "#2ecc71"],
                    borderColor: ["#ffffff", "#ffffff", "#ffffff"],
                    borderWidth: 2,
                },
            ],
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: "none",
                },
                tooltip: {
                    callbacks: {
                        label: function(tooltipItem) {
                            return tooltipItem.label + " vulnerabilities";
                        },
                    },
                },
            },
        },
    });
}
