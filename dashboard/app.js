const ws = new WebSocket("ws://localhost:8000/ws/telemetry");
const statusIndicator = document.getElementById("connection-status");
const trafficRateEl = document.getElementById("traffic-rate");
const activeFlowsEl = document.getElementById("active-flows");
const totalAlertsEl = document.getElementById("total-alerts");
const alertsBody = document.getElementById("alerts-body");

let totalAlerts = 0;
let activeFlows = new Set();
let threatCounts = {
    "BENIGN": 0,
    "DDOS": 0,
    "C2_BEACONING": 0,
    "DNS_DGA_TUNNEL": 0,
    "ENCRYPTED_MALWARE": 0,
    "RECON_PORT_SCAN": 0,
    "DATA_EXFILTRATION": 0
};

// Initialize Chart
const ctx = document.getElementById('threatChart').getContext('2d');
const threatChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: Object.keys(threatCounts),
        datasets: [{
            label: 'Detections',
            data: Object.values(threatCounts),
            backgroundColor: [
                '#10b981', // Benign
                '#ef4444', // DDoS
                '#f59e0b', // C2
                '#8b5cf6', // DNS
                '#ec4899', // Malware
                '#3b82f6', // Recon
                '#f97316'  // Exfil
            ]
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false }
        },
        scales: {
            y: { beginAtZero: true }
        }
    }
});

ws.onopen = () => {
    statusIndicator.textContent = "Connected";
    statusIndicator.className = "connected";
};

ws.onclose = () => {
    statusIndicator.textContent = "Disconnected";
    statusIndicator.className = "disconnected";
};

ws.onmessage = (event) => {
    try {
        const data = JSON.parse(event.data);
        
        if (data.type === "flow_update") {
            // Update active flows set
            activeFlows.add(data.flow_id);
            activeFlowsEl.textContent = activeFlows.size;
            
            // Just display some fake traffic rate based on packets for demo
            if (data.features && data.features.window_packets_per_sec) {
                trafficRateEl.textContent = data.features.window_packets_per_sec.toFixed(2) + " pkts/s";
            }

            // We simulate a detection using the mock class or if there's an actual prediction
            let threatClass = data.prediction || "BENIGN";
            let confidence = data.confidence || 0.99;
            
            if (threatClass !== "BENIGN") {
                totalAlerts++;
                totalAlertsEl.textContent = totalAlerts;
                
                // Add to table
                const row = document.createElement("tr");
                row.innerHTML = `
                    <td>${new Date(data.timestamp * 1000).toLocaleTimeString()}</td>
                    <td>${data.flow_id}</td>
                    <td class="alert-high">${threatClass}</td>
                    <td>${(confidence * 100).toFixed(1)}%</td>
                `;
                alertsBody.insertBefore(row, alertsBody.firstChild);
                
                // Keep only last 10
                if (alertsBody.children.length > 10) {
                    alertsBody.removeChild(alertsBody.lastChild);
                }
            }
            
            if (threatCounts[threatClass] !== undefined) {
                threatCounts[threatClass]++;
                threatChart.data.datasets[0].data = Object.values(threatCounts);
                threatChart.update();
            }
        }
    } catch (e) {
        console.error("Error parsing message", e);
    }
};
