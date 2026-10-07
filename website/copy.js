// Click-to-copy for the install chips. Shared by every page, and it binds
// every `.cmd[data-cmd]` on the page rather than one id, so adding another
// chip needs no script change.
(function () {
  var chips = document.querySelectorAll(".cmd[data-cmd]");
  if (!chips.length) return;

  // execCommand is deprecated but still the only path that works when the page
  // is opened over plain http or from a file:// URL, where navigator.clipboard
  // is undefined. Worth keeping: people do read this page off a local checkout.
  function legacyCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.cssText = "position:fixed;top:-1000px;opacity:0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  Array.prototype.forEach.call(chips, function (btn) {
    var toast = btn.querySelector(".toast");
    // The live region is the element right after the button, when there is one.
    var status = btn.nextElementSibling;
    if (!status || status.getAttribute("role") !== "status") status = null;
    var timer;

    function settle(ok) {
      clearTimeout(timer);
      btn.classList.remove("is-copied", "is-failed");
      btn.classList.add(ok ? "is-copied" : "is-failed");
      if (toast) toast.textContent = ok ? "Copied" : "Press ⌘C";
      if (status) {
        status.textContent = ok
          ? "Command copied to clipboard"
          : "Copy failed, select and copy manually";
      }
      timer = setTimeout(function () {
        btn.classList.remove("is-copied", "is-failed");
        if (toast) toast.textContent = "Copied";
        if (status) status.textContent = "";
      }, 1800);
    }

    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-cmd");
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(
          function () {
            settle(true);
          },
          function () {
            settle(legacyCopy(text));
          }
        );
      } else {
        settle(legacyCopy(text));
      }
    });
  });
})();
