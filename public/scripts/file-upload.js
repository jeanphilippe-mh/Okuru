(() => {
  "use strict";
  const input = document.getElementById("files");
  const form = document.getElementById("file_create");
  const list = document.getElementById("selected-files");
  const error = document.getElementById("file-errors");
  const maxSize = Number(input.dataset.maxSize);
  let selected = [];
  let valid = true;

  function refresh() {
    const transfer = new DataTransfer();
    selected.forEach(file => transfer.items.add(file));
    input.files = transfer.files;
    list.replaceChildren();
    selected.forEach((file, index) => {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = `${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MiB) `;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn btn-sm btn-outline-secondary";
      remove.textContent = "Remove";
      remove.setAttribute("aria-label", `Remove ${file.name}`);
      remove.addEventListener("click", () => {
        selected.splice(index, 1);
        refresh();
      });
      item.append(label, remove);
      list.append(item);
    });
    const total = selected.reduce((sum, file) => sum + file.size, 0);
    const oversized = selected.some(file => file.size > maxSize);
    const duplicateNames = new Set(selected.map(file => file.name)).size !== selected.length;
    valid = !oversized && total <= maxSize && !duplicateNames;
    error.textContent = duplicateNames
      ? "Files must have different names. Please rename duplicate files."
      : !valid ? "The selected files exceed the total upload size limit. Remove files to continue." : "";
  }

  input.addEventListener("change", () => {
    Array.from(input.files).forEach(file => {
      // Selecting the same file again must not add another copy.
      if (!selected.some(existing => existing.name === file.name &&
          existing.size === file.size && existing.lastModified === file.lastModified)) {
        selected.push(file);
      }
    });
    refresh();
  });
  form.addEventListener("submit", event => {
    refresh();
    if (!valid || selected.length === 0) {
      event.preventDefault();
      if (!selected.length) error.textContent = "Please select at least one file.";
    }
  });
  const ttl = document.getElementById("ttl");
  ttl.addEventListener("input", () => {
    const value = Number(ttl.value);
    document.getElementById("ttl-value").textContent = value === 1 ? "1 hour" :
      value <= 24 ? `${value} hours` : `${value - 23} days`;
  });
  const views = document.getElementById("ttlViews");
  views.addEventListener("input", () => {
    document.getElementById("ttlViews-value").textContent =
      Number(views.value) === 1 ? "1 view" : `${views.value} views`;
  });
})();
