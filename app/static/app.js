document.addEventListener("DOMContentLoaded", () => {
  const username = document.getElementById("username-field");
  const deviceName = document.getElementById("device-name-field");
  const passwordDisplay = document.getElementById("p12-password-display");

  if (!username || !deviceName || !passwordDisplay) {
    return;
  }

  const sync = () => {
    const usernameValue = (username.value || "").toLowerCase();
    const deviceValue = (deviceName.value || "").toLowerCase();
    if (username.value !== usernameValue) {
      username.value = usernameValue;
    }
    if (deviceName.value !== deviceValue) {
      deviceName.value = deviceValue;
    }
    passwordDisplay.value = usernameValue;
  };

  username.addEventListener("input", sync);
  deviceName.addEventListener("input", sync);
  sync();
});
