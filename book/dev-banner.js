// Marks the book built from `main`, served under `/dev/`, as the development version (spec §11).
// mdBook defines `path_to_root` on every page, so this works at any chapter depth.
(function () {
  "use strict";
  if (typeof path_to_root !== "string") return;
  const root = new URL(path_to_root || "./", window.location.href);
  if (!root.pathname.endsWith("/dev/")) return;
  const main = document.querySelector("main");
  if (!main) return;
  const banner = document.createElement("p");
  banner.className = "warning";
  banner.style.cssText = "border-left: 4px solid #e0a800; padding: 0.5em 1em;";
  banner.innerHTML =
    "This is the <strong>development version</strong> of the book, built from <code>main</code>. " +
    'See the <a href="' + new URL("../", root).href + '">book of the latest release</a>.';
  main.prepend(banner);
})();
