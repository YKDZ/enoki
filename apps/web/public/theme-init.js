(() => {
  const storageKey = "enoki-theme-mode";
  const storedMode = localStorage.getItem(storageKey);
  const mode =
    storedMode === "light" || storedMode === "dark" || storedMode === "auto"
      ? storedMode
      : "auto";
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const isDark = mode === "dark" || (mode === "auto" && prefersDark);

  document.documentElement.classList.toggle("dark", isDark);
  document.documentElement.style.colorScheme = isDark ? "dark" : "light";
})();
