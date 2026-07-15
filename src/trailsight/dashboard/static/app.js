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
