// Dashboard functionality - Simplified version

// Refresh interval in milliseconds
const REFRESH_INTERVAL = 10000;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Initial data load
    loadAllData();
    
    // Set up refresh interval
    setInterval(loadAllData, REFRESH_INTERVAL);
    
    // Set up refresh button
    document.getElementById('refresh-btn').addEventListener('click', loadAllData);
    
    // Initialize charts
    initCharts();
    
    // Initialize map
    initMap();
});

// Global chart objects
let protocolChart = null;
let usernameChart = null;
let passwordChart = null;
let worldMap = null;

// Load all dashboard data
function loadAllData() {
    fetchStats();
    fetchEvents();
    fetchCredentials();
    fetchGeoData();
}

// Fetch statistics
function fetchStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateStats(data);
            updateProtocolChart(data.protocols);
        })
        .catch(error => console.error('Error fetching stats:', error));
}

// Update statistics display
function updateStats(data) {
    document.getElementById('total-connections').textContent = data.total_connections;
    document.getElementById('unique-ips').textContent = data.unique_ips;
    document.getElementById('attack-attempts').textContent = data.attack_attempts;
    document.getElementById('commands-executed').textContent = data.commands_executed;
}

// Fetch recent events
function fetchEvents() {
    fetch('/api/events')
        .then(response => response.json())
        .then(data => {
            updateEventsTable(data);
        })
        .catch(error => console.error('Error fetching events:', error));
}

// Update events table
function updateEventsTable(events) {
    const table = document.getElementById('events-table');
    table.innerHTML = '';
    
    events.slice(0, 10).forEach(event => {
        const row = document.createElement('tr');
        
        // Add event type class
        if (event.type === 'attack') {
            row.classList.add('has-background-danger-light');
        }
        
        // Format timestamp
        const date = new Date(event.timestamp * 1000);
        const timeString = date.toLocaleTimeString();
        
        // Create row cells
        row.innerHTML = `
            <td>${timeString}</td>
            <td>${event.source_ip}</td>
            <td>${event.protocol}</td>
            <td>${event.event_type || event.type}</td>
            <td>${formatDetails(event.data)}</td>
        `;
        
        table.appendChild(row);
    });
}

// Format event details
function formatDetails(data) {
    if (!data) return '';
    
    let details = '';
    for (const [key, value] of Object.entries(data)) {
        if (typeof value !== 'object') {
            details += `${key}: ${value}, `;
        }
    }
    
    return details.slice(0, -2);
}

// Fetch credential data
function fetchCredentials() {
    fetch('/api/credentials')
        .then(response => response.json())
        .then(data => {
            updateCredentialCharts(data);
        })
        .catch(error => console.error('Error fetching credentials:', error));
}

// Update credential charts
function updateCredentialCharts(data) {
    if (usernameChart && data.usernames) {
        usernameChart.data.labels = data.usernames.map(item => item.username);
        usernameChart.data.datasets[0].data = data.usernames.map(item => item.count);
        usernameChart.update();
    }
    
    if (passwordChart && data.passwords) {
        passwordChart.data.labels = data.passwords.map(item => item.password);
        passwordChart.data.datasets[0].data = data.passwords.map(item => item.count);
        passwordChart.update();
    }
}

// Fetch geographic data
function fetchGeoData() {
    fetch('/api/geo')
        .then(response => response.json())
        .then(data => {
            updateMap(data);
        })
        .catch(error => console.error('Error fetching geo data:', error));
}

// Initialize charts
function initCharts() {
    // Protocol distribution chart
    const protocolCtx = document.getElementById('protocol-chart').getContext('2d');
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#3298dc', // blue
                    '#48c774', // green
                    '#ffdd57', // yellow
                    '#f14668', // red
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'right',
                }
            }
        }
    });
    
    // Username chart
    const usernameCtx = document.getElementById('username-chart').getContext('2d');
    usernameChart = new Chart(usernameCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attempts',
                data: [],
                backgroundColor: '#3298dc',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
    
    // Password chart
    const passwordCtx = document.getElementById('password-chart').getContext('2d');
    passwordChart = new Chart(passwordCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attempts',
                data: [],
                backgroundColor: '#f14668',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Update protocol chart
function updateProtocolChart(protocols) {
    if (protocolChart && protocols) {
        const labels = [];
        const data = [];
        
        for (const [protocol, count] of Object.entries(protocols)) {
            labels.push(protocol);
            data.push(count);
        }
        
        protocolChart.data.labels = labels;
        protocolChart.data.datasets[0].data = data;
        protocolChart.update();
    }
}

// Initialize map
function initMap() {
    const width = document.getElementById('map-container').offsetWidth;
    const height = 400;
    
    // Create SVG
    const svg = d3.select('#map-container')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Create projection
    const projection = d3.geoMercator()
        .scale(130)
        .translate([width / 2, height / 1.5]);
    
    // Create path generator
    const path = d3.geoPath()
        .projection(projection);
    
    // Load world map data
    d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
        .then(data => {
            // Draw countries
            svg.append('g')
                .selectAll('path')
                .data(topojson.feature(data, data.objects.countries).features)
                .enter()
                .append('path')
                .attr('d', path)
                .attr('fill', '#e8e8e8')
                .attr('stroke', '#c0c0c0')
                .attr('stroke-width', 0.5);
            
            // Store map objects for later use
            worldMap = {
                svg: svg,
                projection: projection
            };
        });
}

// Update map with attack data
function updateMap(geoData) {
    if (!worldMap) return;
    
    // Remove existing points
    worldMap.svg.selectAll('.attack-point').remove();
    
    // Add attack points
    worldMap.svg.selectAll('.attack-point')
        .data(geoData)
        .enter()
        .append('circle')
        .attr('class', 'attack-point')
        .attr('cx', d => {
            const coords = worldMap.projection([d.longitude, d.latitude]);
            return coords ? coords[0] : 0;
        })
        .attr('cy', d => {
            const coords = worldMap.projection([d.longitude, d.latitude]);
            return coords ? coords[1] : 0;
        })
        .attr('r', d => Math.log(d.count) * 2 + 3)
        .attr('fill', 'rgba(241, 70, 104, 0.7)')
        .attr('stroke', '#fff')
        .attr('stroke-width', 0.5)
        .append('title')
        .text(d => `${d.country}: ${d.count} attacks`);
}
