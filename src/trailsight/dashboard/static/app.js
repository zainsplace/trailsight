const buttons = document.querySelectorAll(".filter button");

buttons.forEach(function (button) {
  button.addEventListener("click", function () {
    const wanted = button.dataset.filter;
    buttons.forEach(function (other) {
      other.setAttribute("aria-pressed", String(other === button));
    });
    document.querySelectorAll(".finding").forEach(function (row) {
      row.hidden = !(wanted === "all" || row.dataset.severity === wanted);
    });
  });
});

const dropzone = document.querySelector(".dropzone");

if (dropzone) {
  const input = dropzone.querySelector(".file-input");
  const chosen = dropzone.querySelector(".chosen");

  input.addEventListener("change", function () {
    const names = Array.from(input.files).map(function (file) {
      return file.name;
    });
    chosen.textContent = names.length ? names.join(", ") : "No files chosen";
    chosen.classList.toggle("has-files", names.length > 0);
  });

  ["dragenter", "dragover"].forEach(function (type) {
    input.addEventListener(type, function () {
      dropzone.classList.add("dragging");
    });
  });
  ["dragleave", "drop"].forEach(function (type) {
    input.addEventListener(type, function () {
      dropzone.classList.remove("dragging");
    });
  });
}

const list = document.querySelector(".findings");

if (list) {
  document.querySelectorAll("button.explain").forEach(function (button) {
    button.addEventListener("click", function () {
      const target = button.closest(".finding").querySelector(".explanation");
      button.disabled = true;
      button.textContent = "Explaining…";
      target.hidden = false;
      target.textContent = "";
      target.classList.remove("failed");
      fetch("/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: list.dataset.scanId,
          index: Number(button.dataset.index),
        }),
      })
        .then(function (response) {
          return response.json().then(function (body) {
            return { ok: response.ok, body: body };
          });
        })
        .then(function (result) {
          if (result.ok) {
            target.textContent = result.body.explanation;
            button.remove();
            return;
          }
          target.textContent = result.body.error;
          target.classList.add("failed");
          button.disabled = false;
          button.textContent = "Explain";
        })
        .catch(function () {
          target.textContent = "Could not reach the local server.";
          target.classList.add("failed");
          button.disabled = false;
          button.textContent = "Explain";
        });
    });
  });
}
