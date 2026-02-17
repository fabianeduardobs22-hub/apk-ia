const alertsNode = document.getElementById("alerts");
const predictionNode = document.getElementById("predictionResult");

function renderAlert(alert) {
  const row = document.createElement("div");
  row.className = "alert";
  row.textContent = `[${alert.severity}] ${alert.message}`;
  alertsNode.prepend(row);
}

const ws = new WebSocket(`ws://${window.location.host}/ws/2`);
ws.onopen = () => ws.send("subscribe");
ws.onmessage = (event) => renderAlert(JSON.parse(event.data));

async function api(path, method = "GET", body = null) {
  const init = {
    method,
    headers: { "Content-Type": "application/json", "X-User": "analyst" },
  };
  if (body) init.body = JSON.stringify(body);
  const response = await fetch(path, init);
  return response.json();
}

document.getElementById("testAlert").onclick = async () => {
  const data = await api("/alerts", "POST", { message: "Preventive anomaly spike", severity: "high" });
  if (data.alert_id) renderAlert({ message: `Alert #${data.alert_id} sent`, severity: "system" });
};

document.getElementById("predictBtn").onclick = async () => {
  const data = await api("/predict", "POST", {
    sequence: [
      [0.2, 0.2, 0.1, 0.3, 0.5, 0.4, 0.7, 0.6, 0.5, 0.8],
      [0.2, 0.4, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.75, 0.9],
      [0.3, 0.45, 0.5, 0.7, 0.65, 0.7, 0.82, 0.8, 0.9, 0.95],
    ],
  });
  predictionNode.textContent = JSON.stringify(data, null, 2);
};

(function globe() {
  const container = document.getElementById("globe");
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(75, container.clientWidth / container.clientHeight, 0.1, 1000);
  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setSize(container.clientWidth, container.clientHeight);
  container.appendChild(renderer.domElement);

  const geometry = new THREE.SphereGeometry(5, 64, 64);
  const material = new THREE.MeshStandardMaterial({ color: 0x2a79ff, wireframe: true });
  const sphere = new THREE.Mesh(geometry, material);
  scene.add(sphere);

  const light = new THREE.PointLight(0xffffff, 2);
  light.position.set(12, 12, 12);
  scene.add(light);
  camera.position.z = 10;

  function animate() {
    requestAnimationFrame(animate);
    sphere.rotation.y += 0.005;
    renderer.render(scene, camera);
  }
  animate();
})();
