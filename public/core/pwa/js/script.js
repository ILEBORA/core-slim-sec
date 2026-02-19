async function initNotifications() {
  if (!("Notification" in window)) return alert("Notifications not supported");
  const permission = await Notification.requestPermission();
  if (permission !== "granted") return;

  const reg = await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array('BPHtkaTbxbR70yBF6kLDoK8khqi_-rVuZ_zL13TF1jmYFO441ssXNf0b98P376RKJH4KmbzkhlR7BS2lKBlaaZU')
  });

  // Send subscription to server
  await fetch("pwa/subscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(sub)
  });
}

// Helper to convert VAPID key
function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  const rawData = atob(base64);
  return Uint8Array.from([...rawData].map(char => char.charCodeAt(0)));
}

document.addEventListener('DOMContentLoaded', () => {
  initNotifications();
});


// navigator.vibrate([200, 100, 200]);

if ('DeviceOrientationEvent' in window) {
  window.addEventListener('deviceorientation', e => {
    console.log(`Alpha: ${e.alpha}, Beta: ${e.beta}, Gamma: ${e.gamma}`);
  });
}

if ('Accelerometer' in window) {
  const sensor = new Accelerometer({frequency: 60});
  sensor.addEventListener('reading', () => {
    console.log(sensor.x, sensor.y, sensor.z);
  });
  sensor.start();
}

if (navigator.serviceWorker.controller) {
  navigator.serviceWorker.controller.postMessage({
    type: 'SET_BADGE',
    count: 5 // dynamically set
  });
}

//
// Detect when app is opened via ilebora:// link
const urlParams = new URLSearchParams(window.location.search);
const action = urlParams.get('action');

if (action) {
  console.log("Opened via ilebora:// with action:", action);

  switch (action) {
    case 'home':
      // Navigate to home
      window.location.href = '/';
      break;
    case 'chat':
      window.location.href = '/chat';
      break;
    case 'profile':
      window.location.href = '/user/profile';
      break;
    default:
      console.log('Unknown ilebora action:', action);
  }
}