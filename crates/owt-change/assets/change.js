// owt-change: a floating "Request a change" button for a site's signed-in admins.
// Served by owt_change's routes; the page's <script data-endpoint> says where to
// post. Builds its DOM with textContent only (no innerHTML) and styles it with the
// owt-change-* classes, so it runs under a CSP without 'unsafe-inline'.
(() => {
  "use strict";
  const script = document.currentScript;
  const endpoint = script && script.dataset.endpoint;
  if (!endpoint || document.querySelector(".owt-change-button")) return;

  const LABEL = "Request a change";
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  };
  const squash = (text, max) => (text || "").replace(/\s+/g, " ").trim().slice(0, max);

  const button = make("button", "owt-change-button", LABEL);
  button.type = "button";
  document.body.append(button);

  let picking = false;
  let target = null;
  let selection = "";
  const ours = (node) => node instanceof Element && node.closest(".owt-change-button, .owt-change-dialog");

  // A short CSS path: up to four steps, stopping at an id.
  const selectorOf = (node) => {
    const steps = [];
    for (let el = node; el && el.nodeType === 1 && el !== document.body && steps.length < 4; el = el.parentElement) {
      if (el.id) {
        steps.unshift(`#${CSS.escape(el.id)}`);
        break;
      }
      let step = el.localName;
      const cls = [...el.classList].find((c) => !c.startsWith("owt-change"));
      if (cls) step += `.${CSS.escape(cls)}`;
      const parent = el.parentElement;
      if (parent) {
        const same = [...parent.children].filter((c) => c.localName === el.localName);
        if (same.length > 1) step += `:nth-of-type(${same.indexOf(el) + 1})`;
      }
      steps.unshift(step);
    }
    return steps.join(" > ");
  };

  const mark = (node) => {
    if (target) target.classList.remove("owt-change-target");
    target = node;
    if (target) target.classList.add("owt-change-target");
  };

  const stop = () => {
    picking = false;
    document.documentElement.classList.remove("owt-change-picking");
    button.textContent = LABEL;
    document.removeEventListener("pointerover", over, true);
    document.removeEventListener("click", pick, true);
    document.removeEventListener("keydown", escape, true);
  };
  const over = (event) => {
    if (!ours(event.target)) mark(event.target);
  };
  const escape = (event) => {
    if (event.key === "Escape") {
      stop();
      mark(null);
    }
  };
  const pick = (event) => {
    if (ours(event.target)) return;
    // The click picks; it does not follow the link or press the button under it.
    event.preventDefault();
    event.stopPropagation();
    mark(event.target);
    stop();
    open(event.target);
  };

  // Text selected before pressing the button survives the press, not the pick.
  button.addEventListener("pointerdown", () => {
    selection = squash(String(window.getSelection() || ""), 2000);
  });
  button.addEventListener("click", () => {
    if (picking) {
      stop();
      mark(null);
      return;
    }
    picking = true;
    document.documentElement.classList.add("owt-change-picking");
    button.textContent = "Click the part to change (Esc to cancel)";
    document.addEventListener("pointerover", over, true);
    document.addEventListener("click", pick, true);
    document.addEventListener("keydown", escape, true);
  });

  const open = (picked) => {
    const dialog = make("dialog", "owt-change-dialog");
    const form = make("form");
    form.method = "dialog";
    form.append(make("h2", "owt-change-heading", LABEL));
    const about = squash(picked.innerText || picked.textContent, 300);
    if (about) {
      const quote = make("p", "owt-hint", "About: ");
      quote.append(make("q", null, about.length > 120 ? `${about.slice(0, 120)}…` : about));
      form.append(quote);
    }
    const field = (labelText, control) => {
      const wrap = make("div", "owt-field");
      const label = make("label", "owt-label", labelText);
      control.id = `owt-change-${Math.random().toString(36).slice(2)}`;
      label.htmlFor = control.id;
      wrap.append(label, control);
      form.append(wrap);
      return control;
    };
    const title = field("What should change? (a short title)", make("input", "owt-input"));
    title.required = true;
    title.maxLength = 200;
    const detail = field("Tell us more: what you'd like instead, and why", make("textarea", "owt-input owt-change-detail"));
    detail.maxLength = 5000;
    const status = make("p", "owt-change-status");
    status.setAttribute("role", "status");
    const actions = make("div", "owt-change-actions");
    const cancel = make("button", "owt-change-cancel", "Cancel");
    cancel.type = "button";
    const send = make("button", "owt-change-send", "Send");
    send.type = "submit";
    actions.append(cancel, send);
    form.append(status, actions);
    dialog.append(form);
    document.body.append(dialog);

    const close = () => {
      dialog.close();
      dialog.remove();
      mark(null);
    };
    cancel.addEventListener("click", close);
    dialog.addEventListener("cancel", () => mark(null));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      send.disabled = true;
      status.className = "owt-change-status";
      status.textContent = "Sending…";
      const body = {
        title: title.value,
        description: detail.value,
        // Origin and path only: a query or fragment can carry a search, a sign-in
        // link's token or an OAuth code, none of which the tracker should hold.
        page_url: location.origin + location.pathname,
        element: { selector: selectorOf(picked), text: about },
        selection,
        viewport: `${window.innerWidth}x${window.innerHeight}`,
      };
      let sentence = "Couldn't send that request. Try again in a minute.";
      try {
        const response = await fetch(endpoint, {
          method: "POST",
          credentials: "same-origin",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify(body),
        });
        // Only the endpoint's own JSON counts: an expired session is redirected to
        // the sign-in page, which fetch follows to a 200.
        const json = (response.headers.get("content-type") || "").startsWith("application/json");
        const reply = json ? await response.json().catch(() => null) : null;
        if (response.ok && reply && reply.sent === true) {
          status.textContent = "Sent. Thank you!";
          setTimeout(close, 1500);
          return;
        }
        if (!json) sentence = "You've been signed out. Sign in again in another tab, then press Send.";
        else if (reply && typeof reply.error === "string") sentence = reply.error;
      } catch (_) {
        // Offline or blocked: the default sentence says what to do.
      }
      status.className = "owt-change-status owt-field-error";
      status.textContent = sentence;
      send.disabled = false;
    });
    dialog.showModal();
    title.focus();
  };
})();
