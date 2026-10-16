// SSO admin UI (v1.3d): progressive enhancement only; every page works without JavaScript.
(function () {
  "use strict";
  document.addEventListener("click", function (ev) {
    var b = ev.target.closest && ev.target.closest("button.copy");
    if (!b) return;
    var el = document.getElementById(b.getAttribute("data-copy"));
    if (el && navigator.clipboard) {
      navigator.clipboard.writeText(el.textContent.trim()).then(function () { b.textContent = "Copied"; });
    }
  });
  // type-to-confirm: keep the submit button disabled until the name matches
  document.querySelectorAll("input[data-must-equal]").forEach(function (inp) {
    var btn = inp.form && inp.form.querySelector("button[type=submit]");
    if (!btn) return;
    var check = function () { btn.disabled = inp.value !== inp.getAttribute("data-must-equal"); };
    inp.addEventListener("input", check);
    check();
  });
})();
