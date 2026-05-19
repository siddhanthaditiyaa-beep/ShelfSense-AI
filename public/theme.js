(function() {
  const saved = localStorage.getItem("rm-theme") || "system";
  applyTheme(saved);

  function applyTheme(preference) {
    const root = document.documentElement;
    if (preference === "dark") {
      root.setAttribute("data-theme", "dark");
    } else if (preference === "light") {
      root.removeAttribute("data-theme");
    } else {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      if (prefersDark) {
        root.setAttribute("data-theme", "dark");
      } else {
        root.removeAttribute("data-theme");
      }
    }
  }

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    const saved = localStorage.getItem("rm-theme") || "system";
    if (saved === "system") applyTheme("system");
  });

  window.setTheme = function(preference) {
    localStorage.setItem("rm-theme", preference);
    applyTheme(preference);

    // Update active state
    document.querySelectorAll(".theme-option").forEach(opt => {
      opt.classList.toggle("active", opt.dataset.theme === preference);
    });

    // ⭐ Auto close panel after selection
    setTimeout(() => {
      const panel = document.getElementById("settingsPanel");
      if (panel) panel.classList.remove("open");
    }, 200);
  };

  window.toggleSettings = function() {
    const panel = document.getElementById("settingsPanel");
    if (!panel) return;
    panel.classList.toggle("open");

    // Set active state when opening
    const saved = localStorage.getItem("rm-theme") || "system";
    document.querySelectorAll(".theme-option").forEach(opt => {
      opt.classList.toggle("active", opt.dataset.theme === saved);
    });
  };

  // Close when clicking outside
  document.addEventListener("click", function(e) {
    const panel = document.getElementById("settingsPanel");
    const fab = document.getElementById("settingsFab");
    if (panel && fab && !panel.contains(e.target) && !fab.contains(e.target)) {
      panel.classList.remove("open");
    }
  });

})();