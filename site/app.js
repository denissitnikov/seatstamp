(function () {
  "use strict";

  /* ----------------------------------------
   * 1. Theme Toggle (seatstamp_theme)
   * ---------------------------------------- */
  var themeToggle = document.getElementById("theme-toggle");
  var themeLabel = document.getElementById("theme-label");

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    if (themeLabel) {
      themeLabel.textContent = theme === "dark" ? "Dark" : "Light";
    }
    if (themeToggle) {
      themeToggle.setAttribute(
        "aria-label",
        theme === "dark" ? "Switch to Light theme" : "Switch to Dark theme"
      );
    }
  }

  var initialTheme = document.documentElement.getAttribute("data-theme") || "light";
  applyTheme(initialTheme);

  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
      var next = current === "dark" ? "light" : "dark";
      try {
        localStorage.setItem("seatstamp_theme", next);
      } catch (e) {
        // Ignore storage errors in restricted contexts
      }
      applyTheme(next);
    });
  }

  /* ----------------------------------------
   * 2. Interactive Architecture Schema
   * ---------------------------------------- */
  var FLOW_CONFIG = {
    all: {
      badge: "Complete Map",
      summary: "Everything left of the dashed line runs offline inside the buyer's Mac. Everything right of it is only touched once at purchase, seat transfer, or weekly update check.",
      nodes: ["zone-mac", "mac-app", "keychain", "worker", "cdn", "stripe", "cli"],
      edges: ["checkout", "claim", "ticket", "stripe-check", "update-get", "upload-signed", "keychain-seal"],
      seq: {},
      pulse: false,
      steps: [
        {
          title: "1. Buy once",
          body: "The Stripe checkout ID (<code>cs_live_...</code>) is the license key. The Worker checks Stripe on demand (no webhooks) and signs an Ed25519 <code>LK1-</code> ticket.",
          focusNodes: ["mac-app", "worker", "stripe"],
          focusEdges: ["checkout", "stripe-check", "ticket"]
        },
        {
          title: "2. Run offline",
          body: "The app verifies the <code>LK1-</code> ticket against its built-in public key on every launch. No phone-home, so it works on a plane, forever.",
          focusNodes: ["mac-app", "keychain"],
          focusEdges: ["keychain-seal"]
        },
        {
          title: "3. Ship updates",
          body: "<code>license-tool</code> signs <code>version.json</code> and the <code>.dmg</code> hash on your Mac. The app checks the signature, the sequence number, and the file hash.",
          focusNodes: ["cli", "cdn", "mac-app"],
          focusEdges: ["upload-signed", "update-get"]
        }
      ]
    },
    buy: {
      badge: "One-Time Activation",
      summary: "No sign-up and no customer database: the buyer pays on Stripe, the Worker checks the payment, and the Mac stores a signed ticket in its local vault.",
      nodes: ["zone-mac", "mac-app", "keychain", "worker", "stripe"],
      edges: ["checkout", "claim", "stripe-check", "ticket", "keychain-seal"],
      seq: { checkout: "1", claim: "2", "stripe-check": "3", ticket: "4", "keychain-seal": "5" },
      pulse: true,
      steps: [
        {
          title: "Step 1 · Checkout",
          body: "The app makes a random <code>chk_</code> token, opens the Payment Link in the browser, and the handoff is bound to the first Mac that polls for it.",
          focusNodes: ["mac-app", "stripe"],
          focusEdges: ["checkout"]
        },
        {
          title: "Step 2 · Edge check",
          body: "The Worker reads the session, refund and dispute status from Stripe, claims a seat in the record for <code>SHA-256(domain + key)</code>, and can send one backup email.",
          focusNodes: ["worker", "stripe"],
          focusEdges: ["claim", "stripe-check"]
        },
        {
          title: "Step 3 · Seal locally",
          body: "The Worker returns the signed <code>LK1-</code> ticket and the <code>cs_live_...</code> key. The app checks the signature and saves both in its vault (a file in Application Support, mirrored to the Keychain).",
          focusNodes: ["mac-app", "keychain"],
          focusEdges: ["ticket", "keychain-seal"]
        }
      ]
    },
    offline: {
      badge: "The Airplane Test",
      summary: "No network calls. Your Worker, Stripe, and website can all be down, and paid copies still open instantly.",
      nodes: ["zone-mac", "mac-app", "keychain"],
      edges: ["keychain-seal"],
      seq: { "keychain-seal": "1" },
      pulse: true,
      steps: [
        {
          title: "Step 1 · Read the vault",
          body: "On launch, SeatStamp reads the stored <code>LK1-</code> ticket, or the sealed 4-anchor trial clock while the trial runs.",
          focusNodes: ["keychain"],
          focusEdges: ["keychain-seal"]
        },
        {
          title: "Step 2 · Verify math",
          body: "It checks the Ed25519 signature with the public key built into the app, that the seat code is this Mac's, and that <code>issued</code> is not before <code>revokedBefore</code>.",
          focusNodes: ["mac-app"],
          focusEdges: ["keychain-seal"]
        },
        {
          title: "Step 3 · Zero network",
          body: "The app unlocks without waiting on anything. Your servers could be gone for good and paid copies keep working.",
          focusNodes: ["mac-app", "keychain"],
          focusEdges: []
        }
      ]
    },
    update: {
      badge: "Signed Static Updates",
      summary: "Updates are plain static files signed on your Mac. No update server to run, and a swapped download or a refunded order is caught automatically.",
      nodes: ["zone-mac", "mac-app", "cdn", "cli"],
      edges: ["upload-signed", "update-get"],
      seq: { "upload-signed": "1", "update-get": "2" },
      pulse: true,
      steps: [
        {
          title: "Step 1 · Sign release",
          body: "You run <code>license-tool --sign-manifest version.json --artifact App.dmg</code> to sign the version, URL, <code>.dmg</code> SHA-256 and size, and <code>manifest_seq</code>.",
          focusNodes: ["cli"],
          focusEdges: ["upload-signed"]
        },
        {
          title: "Step 2 · Weekly GET",
          body: "At most once a week the app fetches <code>version.json</code> (after an error it waits 1 hour, then 2, 4, up to a week), refuses an older <code>manifest_seq</code>, and checks <code>revoked_tags</code>.",
          focusNodes: ["cdn", "mac-app"],
          focusEdges: ["update-get"]
        },
        {
          title: "Step 3 · Safe download",
          body: "A built-in download checks the SHA-256 and size before the file reaches Downloads, and keeps the quarantine flag so Gatekeeper still checks it.",
          focusNodes: ["mac-app", "cdn"],
          focusEdges: ["update-get"]
        }
      ]
    },
    move: {
      badge: "Bounded Seat Transfer",
      summary: "Moving to a new Mac: the old Mac refuses its own ticket from then on, the Worker spends one move from the yearly budget, and the new Mac gets a fresh ticket.",
      nodes: ["zone-mac", "mac-app", "keychain", "worker"],
      edges: ["keychain-seal", "claim", "ticket"],
      seq: { "keychain-seal": "1", claim: "2", ticket: "3" },
      pulse: true,
      steps: [
        {
          title: "Step 1 · Deactivate Mac #1",
          body: "The old Mac first raises its local <code>revokedBefore</code> cutoff (so its old <code>LK1-</code> ticket can't be pasted back) and then tells the Worker.",
          focusNodes: ["keychain", "mac-app"],
          focusEdges: ["keychain-seal"]
        },
        {
          title: "Step 2 · Budget check",
          body: "The Worker frees the seat if the purchase is within <code>SEAT_RELEASES_PER_YEAR</code> (by default equal to the seat count), which bounds how many Macs one purchase can reach.",
          focusNodes: ["worker"],
          focusEdges: ["claim"]
        },
        {
          title: "Step 3 · Activate Mac #2",
          body: "The new Mac activates with the same <code>cs_live_...</code> key (Migration Assistant carries it over) and gets a ticket bound to its own seat code.",
          focusNodes: ["mac-app", "worker", "keychain"],
          focusEdges: ["ticket", "keychain-seal"]
        }
      ]
    }
  };

  var NODE_ORDER = ["mac-app", "keychain", "worker", "stripe", "cdn", "cli"];
  var NODE_DETAILS = {
    "mac-app": {
      title: "Mac App (SeatStamp)",
      plain: "Verifies the buyer's signed ticket on every launch with the public key built into your app. No internet needed.",
      secrets: "None. Only the license and update public keys, which can verify but not sign.",
      storage: "In-memory verification state",
      safety: "Non-https activation endpoints are dropped (debug builds assert), and a build without endpoints returns .unconfigured instead of .invalidKey"
    },
    "keychain": {
      title: "Local Vault",
      plain: "Holds the purchase key, the signed ticket, and the sealed trial clock, so neither a clock rollback nor an old ticket from a backup gets around the limits.",
      secrets: "The buyer's cs_live_... purchase key and signed LK1- ticket",
      storage: ".license_vault in Application Support (mirrored to the Keychain when signed), plus HMAC-sealed trial timestamps first, high and revokedBefore in 4 places",
      safety: "A clock rollback can't lower first or high, and nothing lowers revokedBefore"
    },
    "worker": {
      title: "Cloudflare Worker + DO",
      plain: "A small Worker that checks Stripe when a Mac activates, signs its ticket, and counts seats under a hash of the purchase key. It never stores emails.",
      secrets: "ED25519_PKCS8_B64 (license signing key), restricted STRIPE_SECRET_KEY, optional RESEND_API_KEY, ADMIN_TOKEN and SEAT_PEPPER",
      storage: "One SQLite Durable Object per purchase, named by SHA-256(domain + key): seat codes, timestamps, yearly release log. Released seats are purged after 30 days",
      safety: "Never wipe on doubt: Stripe errors, pending payments, and won disputes never delete valid seats"
    },
    "stripe": {
      title: "Stripe (+ Resend)",
      plain: "The source of truth for purchases, refunds, and disputes, so you don't run your own customer database or webhooks.",
      secrets: "Your Stripe account (and optional Resend account)",
      storage: "Hosted checkout records in your Stripe account",
      safety: "Restricted key uses 4 read-only scopes (Checkout Sessions, PaymentIntents, Charges, Disputes); zero webhooks"
    },
    "cdn": {
      title: "Static Host / CDN",
      plain: "Any static host (your website, GitHub Releases, R2, S3) serves the signed files. There is no update server to run.",
      secrets: "None (public static files)",
      storage: "version.json and App.dmg",
      safety: "If the host fails, the app waits 1 hour, then 2, 4, and so on up to a week, instead of retrying constantly"
    },
    "cli": {
      title: "Dev CLI (license-tool)",
      plain: "Runs on your own Mac when you ship a release, to sign the manifest and the disk image hash. The update key never touches CI or a server.",
      secrets: "The update private key (and a backup of the license private key), in ~/.seatstamp",
      storage: "Your version.json, signed in place",
      safety: "--unrevoke-key reverses mistaken revocations; --rotate-keypair supports graceful signing-key rotation"
    }
  };

  var flowTabs = Array.prototype.slice.call(document.querySelectorAll(".flow-tab"));
  var archSvg = document.getElementById("arch-svg");
  var archPanel = document.getElementById("arch-panel");
  var flowStepsEl = document.getElementById("flow-steps");
  var flowBannerBadge = document.getElementById("flow-banner-badge");
  var flowBannerText = document.getElementById("flow-banner-text");
  var allNodeEls = Array.prototype.slice.call(document.querySelectorAll("[data-node]"));
  var allEdgeEls = Array.prototype.slice.call(document.querySelectorAll("[data-edge]"));
  var allSeqEls = Array.prototype.slice.call(document.querySelectorAll("[data-seq-for]"));

  function clearStepHover() {
    allNodeEls.forEach(function (el) { el.classList.remove("is-step-hover"); });
    allEdgeEls.forEach(function (el) { el.classList.remove("is-step-hover"); });
  }

  function applyStepHover(stepSpec) {
    clearStepHover();
    if (!stepSpec) return;
    stepSpec.focusNodes.forEach(function (nodeId) {
      document.querySelectorAll('.svg-node[data-node="' + nodeId + '"]').forEach(function (el) {
        el.classList.add("is-step-hover");
      });
    });
    stepSpec.focusEdges.forEach(function (edgeId) {
      document.querySelectorAll('.svg-edge[data-edge="' + edgeId + '"]').forEach(function (el) {
        el.classList.add("is-step-hover");
      });
    });
  }

  function setFlow(flowId, updateHash) {
    if (!FLOW_CONFIG[flowId]) {
      flowId = "all";
    }
    var cfg = FLOW_CONFIG[flowId];

    flowTabs.forEach(function (tab) {
      var active = tab.getAttribute("data-flow") === flowId;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("tabindex", active ? "0" : "-1");
      if (active && archPanel) {
        archPanel.setAttribute("aria-labelledby", tab.id);
      }
    });

    if (flowBannerBadge) flowBannerBadge.textContent = cfg.badge;
    if (flowBannerText) flowBannerText.textContent = cfg.summary;

    if (archSvg) {
      archSvg.classList.toggle("is-pulsing", cfg.pulse);
    }

    allNodeEls.forEach(function (el) {
      var nodeId = el.getAttribute("data-node");
      el.classList.toggle("is-dimmed", cfg.nodes.indexOf(nodeId) === -1);
    });

    allEdgeEls.forEach(function (el) {
      var edgeId = el.getAttribute("data-edge");
      el.classList.toggle("is-dimmed", cfg.edges.indexOf(edgeId) === -1);
    });

    allSeqEls.forEach(function (seqGroup) {
      var edgeId = seqGroup.getAttribute("data-seq-for");
      var num = cfg.seq[edgeId];
      if (num) {
        seqGroup.removeAttribute("hidden");
        var txt = seqGroup.querySelector(".seq-text");
        if (txt) txt.textContent = num;
      } else {
        seqGroup.setAttribute("hidden", "");
      }
    });

    if (flowStepsEl) {
      flowStepsEl.innerHTML = cfg.steps
        .map(function (step, idx) {
          return (
            '<article class="step-card" data-step-idx="' + idx + '" tabindex="0">' +
            '<h3 class="step-card-title">' + step.title + "</h3>" +
            '<p class="step-card-body">' + step.body + "</p>" +
            "</article>"
          );
        })
        .join("");

      Array.prototype.slice.call(flowStepsEl.querySelectorAll(".step-card")).forEach(function (card, idx) {
        var stepSpec = cfg.steps[idx];
        card.addEventListener("mouseenter", function () {
          card.classList.add("is-highlighted");
          applyStepHover(stepSpec);
        });
        card.addEventListener("mouseleave", function () {
          card.classList.remove("is-highlighted");
          clearStepHover();
        });
        card.addEventListener("focus", function () {
          card.classList.add("is-highlighted");
          applyStepHover(stepSpec);
        });
        card.addEventListener("blur", function () {
          card.classList.remove("is-highlighted");
          clearStepHover();
        });
      });
    }

    if (updateHash && window.history && window.history.replaceState) {
      window.history.replaceState(null, "", "#flow=" + flowId);
    }
  }

  flowTabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      setFlow(tab.getAttribute("data-flow"), true);
    });
  });

  enableTablistKeyboard(document.querySelector(".flow-tabs"), flowTabs, function (tab) {
    setFlow(tab.getAttribute("data-flow"), true);
  });

  // Load initial flow from URL hash (#flow=...)
  var hashMatch = window.location.hash.match(/^#flow=([a-z]+)$/);
  setFlow(hashMatch ? hashMatch[1] : "all", false);

  /* Node Detail Drawer */
  var drawerEl = document.getElementById("node-drawer");
  var drawerTitle = document.getElementById("drawer-title");
  var drawerPlain = document.getElementById("drawer-plain");
  var drawerSecrets = document.getElementById("drawer-secrets");
  var drawerStorage = document.getElementById("drawer-storage");
  var drawerSafety = document.getElementById("drawer-safety");
  var drawerClose = document.getElementById("drawer-close");
  var drawerPrev = document.getElementById("drawer-prev");
  var drawerNext = document.getElementById("drawer-next");
  var activeNodeId = null;
  var clickableNodes = Array.prototype.slice.call(
    document.querySelectorAll(".svg-node[data-node], .mobile-node[data-node]")
  );

  function openNodeDrawer(nodeId) {
    var detail = NODE_DETAILS[nodeId];
    if (!detail || !drawerEl) return;
    activeNodeId = nodeId;

    clickableNodes.forEach(function (el) {
      el.classList.toggle("is-selected", el.getAttribute("data-node") === nodeId);
    });

    drawerTitle.textContent = detail.title;
    if (drawerPlain) drawerPlain.textContent = detail.plain;
    drawerSecrets.textContent = detail.secrets;
    drawerStorage.textContent = detail.storage;
    drawerSafety.textContent = detail.safety;
    drawerEl.hidden = false;
  }

  function closeNodeDrawer() {
    if (!drawerEl) return;
    activeNodeId = null;
    drawerEl.hidden = true;
    clickableNodes.forEach(function (el) {
      el.classList.remove("is-selected");
    });
  }

  function stepDrawer(delta) {
    var idx = NODE_ORDER.indexOf(activeNodeId);
    var nextIdx = idx === -1 ? 0 : (idx + delta + NODE_ORDER.length) % NODE_ORDER.length;
    openNodeDrawer(NODE_ORDER[nextIdx]);
  }

  clickableNodes.forEach(function (el) {
    el.addEventListener("click", function () {
      openNodeDrawer(el.getAttribute("data-node"));
    });
    el.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openNodeDrawer(el.getAttribute("data-node"));
      }
    });
  });

  if (drawerClose) drawerClose.addEventListener("click", closeNodeDrawer);
  if (drawerPrev) drawerPrev.addEventListener("click", function () { stepDrawer(-1); });
  if (drawerNext) drawerNext.addEventListener("click", function () { stepDrawer(1); });

  /* ----------------------------------------
   * 3. Inspector: real golden vectors, verified in the browser
   * ---------------------------------------- */
  // Copied from fixtures/golden-vectors.json. site/site.test.mjs fails if they drift.
  var VECTORS = {
    licensePublicKeyBase64: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
    updatePublicKeyBase64: "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=",
    ticket: {
      encoded: "LK1-QUNNRS1WMXxPUkQtNDJBOUYwMUN8MTc2MDAwMDAwMHxiM2Q4ZDVlMDczYTA3NTI0.Nho8x7JiASeN3aPAvuc5rZ761jatIEfTvB3nWIFl-j3_gCQ6wGWshBQ2TilM-vngtaz05sTwA9fEilDql0FeBA",
      seat: "b3d8d5e073a07524"
    },
    manifest: {
      version: "2.0.1",
      url: "https://acme.example/download/Acme-2.0.1.dmg",
      summary: "Sequenced manifest",
      notes: ["Seq bound"],
      revokedTags: [],
      sha256: "53427912b4b3398167ababe6583b6c45fc07f47fcefb8d57da660df0d5a94e16",
      size: 34,
      manifestSeq: 1760000000,
      canonicalUTF8: "ACME-UPDATE-V1\n5:2.0.1\n44:https://acme.example/download/Acme-2.0.1.dmg\n18:Sequenced manifest\nnotes[1]\n9:Seq bound\nsummary_i18n[0]\nnotes_i18n[0]\nartifact_sha256[1]\n64:53427912b4b3398167ababe6583b6c45fc07f47fcefb8d57da660df0d5a94e16\nartifact_size[1]\n2:34\nmanifest_seq[1]\n10:1760000000\n",
      signatureBase64URL: "O8xSCI51vsvIwaWfOpcDQD5b9sdM52S2q3HCEfBTTZNNysJYGiKFMXX0CtOL7AFYQffAqb79vMXCr06yDXfnCA"
    }
  };

  var FIELD_INFO = {
    ticket: {
      prefix: {
        title: "prefix (LK1-)",
        text: "Marks the ticket format. The app only accepts tickets with the prefix it was built with."
      },
      payload: {
        title: "payload (base64url)",
        text: "Four plain fields joined by \"|\". Nothing is encrypted, because nothing is secret: the protection comes from the signature."
      },
      scheme: {
        title: "scheme (ACME-V1)",
        text: "Your app's own name for its licenses. A ticket for one app can't unlock another app that uses SeatStamp, even with the same Stripe account."
      },
      order_tag: {
        title: "order tag (ORD-...)",
        text: "A one-way hash of the purchase key. If the order is refunded, you add this tag to your signed version.json and that copy stops seeing updates, or locks again if you choose."
      },
      issued: {
        title: "issued (unix seconds)",
        text: "When the Worker signed the ticket. After Deactivate, the Mac records a cutoff (revokedBefore), so any ticket issued before it is rejected on that Mac."
      },
      seat: {
        title: "seat (16 hex)",
        text: "A per-app hash of this Mac's hardware ID. The ticket only unlocks the Mac whose seat code matches, so copying it to another Mac does nothing."
      },
      signature: {
        title: "signature (Ed25519, 64 bytes)",
        text: "Made by the Worker with the license private key. The app holds only the public key, which can check a signature but can't make one, so key generators can't exist."
      }
    },
    manifest: {
      version: {
        title: "version",
        text: "The newest version. The app shows an update notice when it's higher than the running one."
      },
      url: {
        title: "url",
        text: "Covered by the signature, and its host must be on the app's list of trusted download hosts. Someone who takes over your server can't point users at their own file."
      },
      summary: { title: "summary", text: "The one-line text of the update notice, also signed." },
      notes: { title: "notes", text: "Release notes shown in the notice, also signed." },
      revoked_tags: {
        title: "revoked_tags",
        text: "Order tags of refunded or disputed purchases. Copies with a matching ticket stop seeing updates (or lock, if you choose), with no license server involved."
      },
      sha256: {
        title: "sha256",
        text: "The exact hash of the .dmg. A built-in download checks it, together with the size, and deletes the file if either differs."
      },
      size: {
        title: "size (bytes)",
        text: "Checked together with sha256, so a truncated or padded download is rejected."
      },
      manifest_seq: {
        title: "manifest_seq",
        text: "Goes up with each signed manifest. The app remembers the highest one it accepted and refuses an older manifest served again."
      },
      sig: {
        title: "sig (Ed25519)",
        text: "Made by license-tool on your own Mac with the update private key, which never goes to Cloudflare. A hacked Worker or CDN can't produce a valid one."
      }
    }
  };

  var inspTabs = Array.prototype.slice.call(document.querySelectorAll(".inspector-tab"));
  var inspPanels = {
    ticket: document.getElementById("insp-panel-ticket"),
    manifest: document.getElementById("insp-panel-manifest")
  };

  function setInspectorTab(artifactId) {
    inspTabs.forEach(function (tab) {
      var active = tab.getAttribute("data-artifact") === artifactId;
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("tabindex", active ? "0" : "-1");
    });
    Object.keys(inspPanels).forEach(function (key) {
      if (inspPanels[key]) {
        inspPanels[key].hidden = key !== artifactId;
      }
    });
  }

  inspTabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      setInspectorTab(tab.getAttribute("data-artifact"));
    });
  });

  enableTablistKeyboard(document.querySelector(".inspector-tabs"), inspTabs, function (tab) {
    setInspectorTab(tab.getAttribute("data-artifact"));
  });

  function selectArtifactField(artifactId, fieldId) {
    var info = FIELD_INFO[artifactId] && FIELD_INFO[artifactId][fieldId];
    if (!info) return;
    var panel = inspPanels[artifactId];
    if (!panel) return;
    var titleEl = document.getElementById(artifactId + "-explain-title");
    var textEl = document.getElementById(artifactId + "-explain-text");
    if (titleEl) titleEl.textContent = info.title;
    if (textEl) textEl.textContent = info.text;
    panel.querySelectorAll("[data-field]").forEach(function (el) {
      el.classList.toggle("is-active", el.getAttribute("data-field") === fieldId);
    });
  }

  ["ticket", "manifest"].forEach(function (artifactId) {
    var panel = inspPanels[artifactId];
    if (!panel) return;
    panel.querySelectorAll("[data-field]").forEach(function (el) {
      var fieldId = el.getAttribute("data-field");
      el.addEventListener("click", function () { selectArtifactField(artifactId, fieldId); });
      el.addEventListener("mouseenter", function () { selectArtifactField(artifactId, fieldId); });
    });
  });

  /* Real Ed25519 verification (WebCrypto). Mirrors LicenseTicket.verify and UpdateManifest.verify. */
  function b64ToBytes(b64) {
    var s = b64.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64URL(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function ed25519Verify(publicKeyB64, signatureBytes, messageBytes) {
    if (!window.crypto || !crypto.subtle) return Promise.reject(new Error("no WebCrypto"));
    return crypto.subtle
      .importKey("raw", b64ToBytes(publicKeyB64), { name: "Ed25519" }, false, ["verify"])
      .then(function (key) {
        return crypto.subtle.verify({ name: "Ed25519" }, key, signatureBytes, messageBytes);
      });
  }

  // Returns "valid", "bad_signature", "wrong_seat", or "revoked".
  function verifyTicket(encoded, expectedSeat, revokedBefore) {
    var body = encoded.slice(4);
    var dot = body.indexOf(".");
    var payload = b64ToBytes(body.slice(0, dot));
    var sig = b64ToBytes(body.slice(dot + 1));
    return ed25519Verify(VECTORS.licensePublicKeyBase64, sig, payload).then(function (ok) {
      if (!ok) return "bad_signature";
      var fields = new TextDecoder().decode(payload).split("|");
      if (fields[3] !== expectedSeat) return "wrong_seat";
      if (revokedBefore > 0 && Number(fields[2]) < revokedBefore) return "revoked";
      return "valid";
    });
  }

  var OTHER_MAC_SEAT = "5f0c9a17e2b4d863";
  var ticketStatusEl = document.getElementById("ticket-sim-status");
  var manifestStatusEl = document.getElementById("manifest-sim-status");

  function setField(id, text, isError) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.classList.toggle("is-error", !!isError);
  }

  function setStatus(el, ok, html) {
    if (!el) return;
    el.className = "sim-status " + (ok ? "is-ok" : "is-fail");
    el.innerHTML = html;
  }

  var NO_ED25519 =
    "<strong>Can't run Ed25519 in this browser.</strong> Safari 17, Chrome 137 and Firefox 129 or newer can. The app itself verifies with CryptoKit.";

  function renderTicket(mode) {
    var encoded = VECTORS.ticket.encoded;
    var macSeat = VECTORS.ticket.seat;
    var revokedBefore = 0;
    var fields = new TextDecoder().decode(b64ToBytes(encoded.slice(4, encoded.indexOf(".")))).split("|");

    if (mode === "tamper") {
      fields[3] = OTHER_MAC_SEAT;
      var edited = new TextEncoder().encode(fields.join("|"));
      encoded = "LK1-" + bytesToB64URL(edited) + encoded.slice(encoded.indexOf("."));
      macSeat = OTHER_MAC_SEAT;
    } else if (mode === "copy") {
      macSeat = OTHER_MAC_SEAT;
    } else if (mode === "replay") {
      revokedBefore = Number(fields[2]) + 50000;
    }

    var dot = encoded.indexOf(".");
    setField("ticket-token-payload", encoded.slice(4, dot), mode === "tamper");
    setField("ticket-token-sig", encoded.slice(dot + 1), false);
    setField("ticket-field-scheme", fields[0], false);
    setField("ticket-field-tag", fields[1], false);
    setField("ticket-field-issued", fields[2], mode === "replay");
    setField("ticket-field-seat", fields[3], mode === "tamper" || mode === "copy");
    var ctx = document.getElementById("ticket-mac-context");
    if (ctx) {
      ctx.textContent = "this Mac's seat: " + macSeat + (revokedBefore ? "   revokedBefore: " + revokedBefore : "   revokedBefore: none");
    }

    verifyTicket(encoded, macSeat, revokedBefore).then(function (result) {
      if (result === "valid") {
        setStatus(ticketStatusEl, true, "<strong>Valid.</strong> Ed25519 signature checked in your browser, seat matches this Mac. No network call.");
      } else if (result === "bad_signature") {
        setStatus(ticketStatusEl, false, "<strong>Rejected: signature doesn't match.</strong> Changing one character of the payload breaks the signature, and only the Worker's private key can make a new one.");
        selectArtifactField("ticket", "signature");
      } else if (result === "wrong_seat") {
        setStatus(ticketStatusEl, false, "<strong>Rejected: wrong Mac.</strong> The signature is fine, but the ticket names another Mac's seat. This Mac has to activate with the purchase key to get its own ticket.");
        selectArtifactField("ticket", "seat");
      } else {
        setStatus(ticketStatusEl, false, "<strong>Rejected: issued before Deactivate.</strong> This Mac gave its seat back, so it refuses any ticket older than that moment, even offline.");
        selectArtifactField("ticket", "issued");
      }
    }, function () {
      setStatus(ticketStatusEl, false, NO_ED25519);
    });
  }

  function renderManifest(mode) {
    var m = VECTORS.manifest;
    var url = m.url;
    var canonical = m.canonicalUTF8;
    if (mode === "url") {
      url = "https://evil.example/download/Acme-2.0.1.dmg";
      canonical = canonical.replace(m.url.length + ":" + m.url, url.length + ":" + url);
    }
    setField("manifest-field-version", '"version": "' + m.version + '"', false);
    setField("manifest-field-url", '"url": "' + url + '"', mode === "url");
    setField("manifest-field-summary", '"summary": "' + m.summary + '"', false);
    setField("manifest-field-notes", '"notes": ' + JSON.stringify(m.notes), false);
    setField("manifest-field-revoked", '"revoked_tags": ' + JSON.stringify(m.revokedTags), false);
    setField("manifest-field-sha256", '"sha256": "' + m.sha256.slice(0, 12) + "..." + m.sha256.slice(-4) + '"', mode === "swap");
    setField("manifest-field-size", '"size": ' + m.size, mode === "swap");
    setField("manifest-field-seq", '"manifest_seq": ' + (mode === "downgrade" ? m.manifestSeq - 86400 : m.manifestSeq), mode === "downgrade");
    setField("manifest-field-sig", '"sig": "' + m.signatureBase64URL.slice(0, 16) + '..."', false);

    if (mode === "downgrade") {
      setStatus(manifestStatusEl, false, "<strong>Rejected: older manifest.</strong> Its signature is valid, but its manifest_seq is lower than the " + m.manifestSeq + " this Mac already accepted, so an old file can't hide a newer update or bring back a revoked key.");
      selectArtifactField("manifest", "manifest_seq");
      return;
    }

    ed25519Verify(VECTORS.updatePublicKeyBase64, b64ToBytes(m.signatureBase64URL), new TextEncoder().encode(canonical)).then(function (ok) {
      if (!ok) {
        setStatus(manifestStatusEl, false, "<strong>Rejected: signature doesn't match.</strong> The URL is part of the signed bytes, so pointing it elsewhere needs your offline update key.");
        selectArtifactField("manifest", "url");
      } else if (mode === "swap") {
        setStatus(manifestStatusEl, false, "<strong>Rejected: download doesn't match.</strong> The manifest is genuine, but the file on the server was replaced. Its SHA-256 differs from the signed one, so the download is deleted before it reaches the Downloads folder.");
        selectArtifactField("manifest", "sha256");
      } else {
        setStatus(manifestStatusEl, true, "<strong>Valid.</strong> Ed25519 signature over the canonical bytes checked in your browser. The download will be checked against sha256 and size.");
      }
    }, function () {
      setStatus(manifestStatusEl, false, NO_ED25519);
    });
  }

  Array.prototype.slice.call(document.querySelectorAll(".sim-btn")).forEach(function (btn) {
    btn.addEventListener("click", function () {
      var group = btn.getAttribute("data-sim-group");
      var mode = btn.getAttribute("data-sim-mode");
      document.querySelectorAll('.sim-btn[data-sim-group="' + group + '"]').forEach(function (b) {
        b.classList.toggle("is-active", b === btn);
      });
      if (group === "ticket") renderTicket(mode);
      if (group === "manifest") renderManifest(mode);
    });
  });

  renderTicket("valid");
  renderManifest("valid");
  selectArtifactField("ticket", "prefix");
  selectArtifactField("manifest", "sha256");

  /* ----------------------------------------
   * 4. 5-Step Developer Setup Switcher
   * ---------------------------------------- */
  var setupTabs = Array.prototype.slice.call(document.querySelectorAll(".setup-step-btn"));
  var setupPanels = Array.prototype.slice.call(document.querySelectorAll(".setup-panel"));

  function setSetupStep(stepNum) {
    setupTabs.forEach(function (tab) {
      var active = tab.getAttribute("data-step") === String(stepNum);
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("tabindex", active ? "0" : "-1");
    });
    setupPanels.forEach(function (panel) {
      panel.hidden = panel.id !== "setup-panel-" + stepNum;
    });
  }

  setupTabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      setSetupStep(tab.getAttribute("data-step"));
    });
  });

  Array.prototype.slice.call(document.querySelectorAll(".setup-nav-btn")).forEach(function (btn) {
    btn.addEventListener("click", function () {
      var targetStep = btn.getAttribute("data-goto-step");
      setSetupStep(targetStep);
      var targetTab = document.getElementById("setup-tab-" + targetStep);
      if (targetTab) targetTab.focus();
    });
  });

  enableTablistKeyboard(document.querySelector(".setup-steps"), setupTabs, function (tab) {
    setSetupStep(tab.getAttribute("data-step"));
  });

  /* Copy buttons */
  var copyButtons = Array.prototype.slice.call(document.querySelectorAll(".copy-btn"));
  copyButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var targetId = btn.getAttribute("data-copy-target");
      var pre = document.getElementById(targetId);
      if (!pre) return;
      var text = pre.textContent || "";

      function markCopied() {
        btn.textContent = "Copied";
        btn.classList.add("is-copied");
        window.setTimeout(function () {
          btn.textContent = "Copy";
          btn.classList.remove("is-copied");
        }, 1600);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(markCopied).catch(function () {
          fallbackCopy(text, markCopied);
        });
      } else {
        fallbackCopy(text, markCopied);
      }
    });
  });

  function fallbackCopy(text, onDone) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand("copy");
      onDone();
    } catch (e) {
      // Ignore copy failure
    }
    document.body.removeChild(area);
  }

  /* ----------------------------------------
   * 5. Scroll-spy for Top Nav Links
   * ---------------------------------------- */
  var navLinks = Array.prototype.slice.call(document.querySelectorAll(".nav-link[data-nav-section]"));
  if ("IntersectionObserver" in window && navLinks.length) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            var id = entry.target.id;
            navLinks.forEach(function (link) {
              link.classList.toggle("is-active", link.getAttribute("data-nav-section") === id);
            });
          }
        });
      },
      { rootMargin: "-30% 0px -55% 0px" }
    );
    navLinks.forEach(function (link) {
      var sec = document.getElementById(link.getAttribute("data-nav-section"));
      if (sec) observer.observe(sec);
    });
  }

  /* ----------------------------------------
   * Shared Keyboard Tablist Helper
   * ---------------------------------------- */
  function enableTablistKeyboard(tablistEl, tabs, onSelect) {
    if (!tablistEl || !tabs.length) return;
    tablistEl.addEventListener("keydown", function (e) {
      var idx = tabs.indexOf(document.activeElement);
      if (idx === -1) return;

      var nextIdx = idx;
      if (e.key === "ArrowRight" || e.key === "ArrowDown") {
        nextIdx = (idx + 1) % tabs.length;
      } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
        nextIdx = (idx - 1 + tabs.length) % tabs.length;
      } else if (e.key === "Home") {
        nextIdx = 0;
      } else if (e.key === "End") {
        nextIdx = tabs.length - 1;
      } else {
        return;
      }

      e.preventDefault();
      tabs[nextIdx].focus();
      onSelect(tabs[nextIdx]);
    });
  }
})();
