// Sign-in page. The X-Decrypt-Viewer header is required by the server for every POST.
const form = document.getElementById("loginForm");
const error = document.getElementById("loginError");
const submit = document.getElementById("loginSubmit");

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  submit.disabled = true;
  error.hidden = true;
  try {
    const r = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Decrypt-Viewer": "1" },
      body: JSON.stringify({ password: document.getElementById("password").value }),
    });
    if (r.ok) {
      location.replace("/");
      return;
    }
    const data = await r.json().catch(() => ({}));
    error.textContent = typeof data.detail === "string" ? data.detail : `Sign-in failed (${r.status}).`;
  } catch (e) {
    error.textContent = `Couldn't reach the server: ${e.message}`;
  }
  error.hidden = false;
  submit.disabled = false;
  document.getElementById("password").select();
});
