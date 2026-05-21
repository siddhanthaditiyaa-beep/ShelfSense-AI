(function() {
  const saved = localStorage.getItem("shelfsense-theme") || "dark";
  applyTheme(saved);

  function applyTheme(theme) {
    const root = document.documentElement;
    if (theme === "system") {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.setAttribute("data-theme", prefersDark ? "dark" : "light");
    } else {
      root.setAttribute("data-theme", theme);
    }
  }

  window.setTheme = function(theme) {
    localStorage.setItem("shelfsense-theme", theme);
    applyTheme(theme);
    updateThemeUI(theme);
    const panel = document.getElementById("settingsPanel");
    if (panel) panel.classList.remove("open");
  };

  window.toggleSettings = function() {
    const panel = document.getElementById("settingsPanel");
    if (panel) {
      panel.classList.toggle("open");
      updateThemeUI(localStorage.getItem("shelfsense-theme") || "dark");
    }
  };

  function updateThemeUI(current) {
    document.querySelectorAll(".theme-option").forEach(opt => {
      opt.classList.toggle("active", opt.dataset.theme === current);
    });
  }

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (localStorage.getItem("shelfsense-theme") === "system") applyTheme("system");
  });

  document.addEventListener("DOMContentLoaded", () => {
    updateThemeUI(localStorage.getItem("shelfsense-theme") || "dark");
  });
})();