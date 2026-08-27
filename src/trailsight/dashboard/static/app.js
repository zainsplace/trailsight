const buttons = document.querySelectorAll(".filter button");

buttons.forEach(function (button) {
  button.addEventListener("click", function () {
    const wanted = button.dataset.filter;
    buttons.forEach(function (other) {
      other.classList.toggle("active", other === button);
    });
    document.querySelectorAll(".finding").forEach(function (card) {
      const show = wanted === "all" || card.dataset.severity === wanted;
      card.style.display = show ? "" : "none";
    });
  });
});

if (buttons.length) {
  buttons[0].classList.add("active");
}

const list = document.querySelector(".findings");

if (list) {
  document.querySelectorAll("button.explain").forEach(function (button) {
    button.addEventListener("click", function () {
      const target = button.parentElement.querySelector(".explanation");
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
