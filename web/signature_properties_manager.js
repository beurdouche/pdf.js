/* Copyright 2026 Mozilla Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AnnotationEditorType, PDFDateString } from "pdfjs-lib";

const STATUS_PRIORITY = {
  invalid: 5,
  revoked: 4,
  expired: 3,
  untrusted: 2,
  unknown: 1,
  verified: 0,
};

function bannerStateForResults(results) {
  if (results.length === 0) {
    return { worst: "unknown", severity: "error", count: 0 };
  }
  let worst = "verified";
  for (const r of results) {
    if (r && r.status && STATUS_PRIORITY[r.status] > STATUS_PRIORITY[worst]) {
      worst = r.status;
    }
  }
  // Count how many signatures are at the worst level — this drives the
  // singular/plural variant of the banner message.
  let count = 0;
  for (const r of results) {
    if (r?.status === worst) {
      count++;
    }
  }
  // The banner reduces to 3 visual severities. The message text still picks
  // the wording specific to `worst`.
  //   verified            → green   (all signatures verified)
  //   untrusted / expired → orange  (signature is cryptographically fine,
  //                                  only cert trust or validity is the
  //                                  issue)
  //   invalid / unknown   → red     (signature itself failed or could not
  //                                  be checked)
  let severity;
  switch (worst) {
    case "verified":
      severity = "verified";
      break;
    case "untrusted":
    case "expired":
      severity = "warn";
      break;
    default:
      severity = "error";
  }
  return { worst, severity, count };
}

// For an `untrusted` certificate, pick the most specific Fluent label /
// args we can — preferring the structured "Certificate: <reason>
// (<issuer>)" form when we recognise the error code, and falling back to
// the generic "Certificate: Untrusted (<reason>)".
function untrustedCertLabel(errorCode, issuerCN) {
  const code = (errorCode || "").toUpperCase();
  const args = issuerCN ? { issuer: issuerCN } : null;
  if (code.includes("UNKNOWN_ISSUER") && args) {
    return {
      id: "pdfjs-signature-properties-certificate-untrusted-unknown-issuer",
      args,
    };
  }
  if (code.includes("SELF_SIGNED") && args) {
    return {
      id: "pdfjs-signature-properties-certificate-untrusted-self-signed",
      args,
    };
  }
  if (code.includes("UNTRUSTED_ISSUER") && args) {
    return {
      id: "pdfjs-signature-properties-certificate-untrusted-untrusted-issuer",
      args,
    };
  }
  const reason = shortCertReason(errorCode);
  if (reason) {
    return {
      id: "pdfjs-signature-properties-certificate-untrusted-with-reason",
      args: { reason },
    };
  }
  return {
    id: "pdfjs-signature-properties-certificate-untrusted",
    args: null,
  };
}

// Map a chrome-side errorCode string to a single short word that fits in the
// "Certificate: Expired (<date>)" / generic "Certificate: Untrusted (<reason>)"
// labels. Returns null when no concise reason is available.
function shortCertReason(errorCode) {
  if (!errorCode || errorCode === "NS_OK") {
    return null;
  }
  const code = errorCode.toUpperCase();
  if (code.includes("UNKNOWN_ISSUER")) {
    return "unknown issuer";
  }
  if (code.includes("UNTRUSTED_ISSUER") || code.includes("UNTRUSTED_CERT")) {
    return "untrusted";
  }
  if (code.includes("SELF_SIGNED")) {
    return "self-signed";
  }
  if (code.includes("REVOKED")) {
    return "revoked";
  }
  if (code.includes("EXPIRED")) {
    return "expired";
  }
  if (code.includes("NOT_YET_VALID")) {
    return "not-yet-valid";
  }
  if (code.includes("KEY_USAGE")) {
    return "key-usage";
  }
  if (code.includes("SIGNATURE")) {
    return "bad-signature";
  }
  return null;
}

// For an `expired` certificate: NSS may have flagged either the leaf
// (SEC_ERROR_EXPIRED_CERTIFICATE) or any issuer up the chain
// (SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE). We want the parenthetical
// to show the date that actually expired, so walk the chain and
// return the first notAfter that is already in the past as a Date.
function expirationDateForCert(cert) {
  if (!cert) {
    return null;
  }
  const now = Date.now();
  const entries =
    Array.isArray(cert.chain) && cert.chain.length ? cert.chain : [cert];
  for (const entry of entries) {
    if (typeof entry?.notAfter === "string" && entry.notAfter) {
      const date = new Date(entry.notAfter);
      const ts = date.getTime();
      if (Number.isFinite(ts) && ts < now) {
        return date;
      }
    }
  }
  if (typeof cert.notAfter === "string" && cert.notAfter) {
    const date = new Date(cert.notAfter);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  return null;
}

class SignaturePropertiesManager {
  #appConfig;

  #verifier;

  #eventBus;

  #signatures = [];

  #results = new Map(); // signatureId -> VerificationResult

  #pendingVerify = new Set(); // signatureId set, in-flight

  #isOpen = false;

  #isLoading = false;

  #docOpen = false;

  constructor({ appConfig, verifier, eventBus }) {
    this.#appConfig = appConfig;
    this.#verifier = verifier;
    this.#eventBus = eventBus;

    appConfig.signaturePropertiesButton.addEventListener("click", () => {
      this.#toggle();
    });
  }

  /**
   * @returns {boolean} `true` while the doorhanger is visible.
   */
  get isOpen() {
    return this.#isOpen;
  }

  /**
   * Close the doorhanger if it is open. The viewer's existing Escape
   * handler and outside-click logic call this — the manager doesn't
   * register its own document-level listeners.
   */
  close() {
    if (this.#isOpen) {
      this.#close();
    }
  }

  /**
   * @param {Element} target Click target. The viewer's outside-click
   *   handler uses this to decide whether to close the panel.
   * @returns {boolean} `true` if the click is outside both the toolbar
   *   button and the doorhanger and the panel should be closed.
   */
  shouldCloseOnClick(target) {
    if (!this.#isOpen) {
      return false;
    }
    return !(
      this.#appConfig.signaturePropertiesButton.contains(target) ||
      this.#appConfig.signaturePropertiesPanel.contains(target)
    );
  }

  async loadFromDocument(pdfDocument) {
    this.#docOpen = true;
    this.#signatures = [];
    this.#results.clear();
    this.#pendingVerify.clear();
    this.#isLoading = true;
    this.#render();

    let signatures;
    try {
      signatures = await pdfDocument.getSignatures();
    } catch (ex) {
      console.warn("getSignatures failed:", ex);
      signatures = [];
    }
    if (!this.#docOpen) {
      // Document closed during fetch.
      return;
    }
    this.#signatures = signatures || [];
    this.#isLoading = false;

    if (this.#signatures.length === 0) {
      this.#hideButton();
      return;
    }
    this.#showButton();

    // Seed each signature with an "unknown" placeholder result so the
    // banner / badge / cards have something to render while the worker
    // verifies them in the background.
    for (const sig of this.#signatures) {
      this.#results.set(sig.id, {
        signatureId: sig.id,
        status: "unknown",
        errorCode: null,
        message: null,
        certificate: null,
        documentModifiedAfterSigning: !sig.coversWholeDocument,
      });
    }
    this.#render();
    this.#updateButtonState();
    // Kick off verification automatically — the toolbar button reflects the
    // aggregate state and updates as each signature resolves.
    for (const sig of this.#signatures) {
      this.#verify(sig);
    }
  }

  reset() {
    this.#docOpen = false;
    this.#signatures = [];
    this.#results.clear();
    this.#pendingVerify.clear();
    this.#hideButton();
    this.#close();
    this.#updateButtonState();
  }

  // --- internal ---

  #showButton() {
    const root = this.#appConfig.signaturePropertiesButton.parentElement;
    if (root) {
      root.hidden = false;
    }
  }

  #hideButton() {
    const root = this.#appConfig.signaturePropertiesButton.parentElement;
    if (root) {
      root.hidden = true;
    }
  }

  #toggle() {
    if (this.#isOpen) {
      this.#close();
    } else {
      this.#open();
    }
  }

  #open() {
    this.#isOpen = true;
    // Close any other open editor doorhanger (Ink, FreeText, Highlight, …)
    // and the find bar / secondary toolbar via global onClick — same pattern
    // the Comment doorhanger uses.
    this.#eventBus?.dispatch("switchannotationeditormode", {
      source: this,
      mode: AnnotationEditorType.NONE,
    });
    this.#eventBus?.dispatch("findbarclose", { source: this });
    this.#appConfig.signaturePropertiesPanel.classList.remove("hidden");
    this.#appConfig.signaturePropertiesButton.setAttribute(
      "aria-expanded",
      "true"
    );
  }

  #close() {
    this.#isOpen = false;
    this.#appConfig.signaturePropertiesPanel.classList.add("hidden");
    this.#appConfig.signaturePropertiesButton.setAttribute(
      "aria-expanded",
      "false"
    );
  }

  #render() {
    const list = this.#appConfig.signaturePropertiesList;
    const banner = this.#appConfig.signaturePropertiesBanner;
    list.replaceChildren();

    if (this.#isLoading) {
      banner.hidden = true;
      for (let i = 0; i < 2; i++) {
        const li = document.createElement("li");
        li.className = "sigCard";
        for (let j = 0; j < 3; j++) {
          const sk = document.createElement("div");
          sk.className = "sigCard__skeleton";
          li.append(sk);
        }
        list.append(li);
      }
      return;
    }

    // Banner.
    const { worst, severity, count } = bannerStateForResults([
      ...this.#results.values(),
    ]);
    banner.replaceChildren();
    banner.hidden = false;
    banner.className = `sigBanner ${severity}`;
    banner.setAttribute(
      "data-l10n-id",
      `pdfjs-signature-properties-banner-${worst}`
    );
    banner.setAttribute("data-l10n-args", JSON.stringify({ count }));

    // Group sub-signatures under their parent.
    const byParent = new Map();
    const topLevel = [];
    for (const sig of this.#signatures) {
      if (sig.parentId) {
        if (!byParent.has(sig.parentId)) {
          byParent.set(sig.parentId, []);
        }
        byParent.get(sig.parentId).push(sig);
      } else {
        topLevel.push(sig);
      }
    }

    // Green icons are reserved for the top-level card when *every*
    // signature in the document is verified. Anywhere else (any
    // sub-signature, or a top-level when something further down is
    // expired/untrusted/etc.) keeps the muted grey check.
    const everythingFine = severity === "verified";

    for (const sig of topLevel) {
      list.append(
        this.#renderCard(sig, byParent, /* depth = */ 0, everythingFine)
      );
    }
  }

  #renderCard(sig, byParent, depth, everythingFine) {
    const subs = byParent.get(sig.id) || [];
    const li = document.createElement("li");
    li.className = "sigCard";
    if (depth === 0 && everythingFine) {
      li.classList.add("sigCard--top-allfine");
    }
    li.dataset.signatureId = sig.id;

    const result = this.#results.get(sig.id);
    const inFlight = this.#pendingVerify.has(sig.id);

    const subjectCN = result?.certificate?.subjectCN;
    if (subjectCN) {
      const signer = document.createElement("div");
      signer.className = "sigCard__signer";
      signer.textContent = subjectCN;
      li.append(signer);
    }

    // Status row.
    const statusRow = document.createElement("div");
    statusRow.className = `sigCard__row status--${result.status}`;
    const statusLabel = document.createElement("span");
    statusLabel.setAttribute(
      "data-l10n-id",
      `pdfjs-signature-properties-status-${result.status}`
    );
    statusRow.append(statusLabel);
    li.append(statusRow);

    if (result.status === "invalid" && result.message) {
      const reason = document.createElement("div");
      reason.className = "sigCard__detail";
      reason.setAttribute("data-l10n-id", "pdfjs-signature-properties-reason");
      reason.setAttribute(
        "data-l10n-args",
        JSON.stringify({ reason: result.message })
      );
      li.append(reason);
    }

    // Certificate row.
    const cert = result.certificate;
    const certRow = document.createElement("div");
    let certKind = "unknown";
    if (cert) {
      switch (result.status) {
        case "verified":
        case "invalid":
          certKind = "trusted";
          break;
        case "expired":
          certKind = "expired";
          break;
        case "revoked":
          certKind = "revoked";
          break;
        case "untrusted":
          certKind = "untrusted";
          break;
        default:
          certKind = "unknown";
      }
    }
    certRow.className = `sigCard__row cert--${certKind}`;
    const certLabel = document.createElement("span");
    let l10nId = `pdfjs-signature-properties-certificate-${certKind}`;
    let l10nArgs = null;
    if (cert?.issuerCN && certKind === "trusted") {
      l10nArgs = { issuer: cert.issuerCN };
    } else if (certKind === "expired") {
      // For expired, the parenthetical is the expiration date itself
      // (could be the leaf or any issuer up the chain). Pass a Date
      // through Fluent so the viewer locale formats it, not the
      // browser locale.
      const date = expirationDateForCert(cert);
      if (date) {
        l10nId = `${l10nId}-with-date`;
        l10nArgs = { dateObj: date.valueOf() };
      }
    } else if (certKind === "untrusted") {
      const label = untrustedCertLabel(result.errorCode, cert?.issuerCN);
      l10nId = label.id;
      l10nArgs = label.args;
    } else if (certKind === "revoked") {
      const reason = shortCertReason(result.errorCode);
      if (reason) {
        l10nId = `${l10nId}-with-reason`;
        l10nArgs = { reason };
      }
    }
    certLabel.setAttribute("data-l10n-id", l10nId);
    if (l10nArgs) {
      certLabel.setAttribute("data-l10n-args", JSON.stringify(l10nArgs));
    }
    certRow.append(certLabel);

    li.append(certRow);

    if (result.status === "untrusted" && result.message) {
      const detail = document.createElement("div");
      detail.className = "sigCard__detail";
      detail.textContent = result.message;
      li.append(detail);
    }
    if (result.status === "expired" && result.message) {
      const detail = document.createElement("div");
      detail.className = "sigCard__detail";
      detail.textContent = result.message;
      li.append(detail);
    }

    if (sig.reason) {
      const reason = document.createElement("div");
      reason.className = "sigCard__detail";
      reason.setAttribute("data-l10n-id", "pdfjs-signature-properties-reason");
      reason.setAttribute(
        "data-l10n-args",
        JSON.stringify({ reason: sig.reason })
      );
      li.append(reason);
    }

    const signingDate = PDFDateString.toDateObject(sig.signingTime);
    if (signingDate) {
      const ts = document.createElement("div");
      ts.className = "sigCard__detail";
      ts.setAttribute("data-l10n-id", "pdfjs-signature-properties-timestamp");
      ts.setAttribute(
        "data-l10n-args",
        JSON.stringify({ dateObj: signingDate.valueOf() })
      );
      li.append(ts);
    }

    if (cert && typeof this.#verifier?.viewCertificate === "function") {
      const viewCert = document.createElement("button");
      viewCert.className = "sigCard__viewCert";
      viewCert.type = "button";
      viewCert.setAttribute(
        "data-l10n-id",
        "pdfjs-signature-properties-view-certificate"
      );
      viewCert.addEventListener("click", e => {
        e.stopPropagation();
        this.#verifier.viewCertificate(cert);
      });
      li.append(viewCert);
    }

    if (subs.length > 0) {
      const subList = document.createElement("ul");
      subList.className = "signaturePropertiesList sigCard__nested";
      for (const sub of subs) {
        subList.append(
          this.#renderCard(sub, byParent, depth + 1, everythingFine)
        );
      }

      if (depth === 0) {
        // Only the top-level card gets the collapsible header. Deeper
        // signatures are always rendered inline; the nested border + indent
        // already shows the parent→child relationship.
        const details = document.createElement("details");
        details.className = "sigCard__subSignatures";
        details.open = true;
        const summary = document.createElement("summary");
        summary.setAttribute(
          "data-l10n-id",
          "pdfjs-signature-properties-sub-signatures"
        );
        summary.setAttribute(
          "data-l10n-args",
          JSON.stringify({ count: this.#countDescendants(sig.id, byParent) })
        );
        details.append(summary);
        details.append(subList);
        li.append(details);
      } else {
        li.append(subList);
      }
    }

    if (inFlight) {
      const sk = document.createElement("div");
      sk.className = "sigCard__skeleton";
      li.append(sk);
    }

    return li;
  }

  #countDescendants(id, byParent) {
    const direct = byParent.get(id);
    if (!direct) {
      return 0;
    }
    let total = direct.length;
    for (const sub of direct) {
      total += this.#countDescendants(sub.id, byParent);
    }
    return total;
  }

  async #verify(signature) {
    if (!this.#verifier || this.#pendingVerify.has(signature.id)) {
      return;
    }
    this.#pendingVerify.add(signature.id);
    this.#render();

    let result;
    try {
      result = await this.#verifier.verify(signature);
    } catch (ex) {
      console.warn("signature verify failed:", ex);
      result = {
        signatureId: signature.id,
        status: "unknown",
        errorCode: "BRIDGE_ERROR",
        message: ex?.message ?? null,
        certificate: null,
        documentModifiedAfterSigning: !signature.coversWholeDocument,
      };
    }
    this.#pendingVerify.delete(signature.id);
    if (!this.#docOpen) {
      return;
    }
    this.#results.set(signature.id, result);
    this.#render();
    this.#updateButtonState();
  }

  #updateButtonState() {
    const button = this.#appConfig.signaturePropertiesButton;
    button.classList.remove(
      "state-loading",
      "state-verified",
      "state-warn",
      "state-error"
    );
    if (this.#signatures.length === 0) {
      return;
    }
    if (this.#pendingVerify.size > 0) {
      button.classList.add("state-loading");
      return;
    }
    let worst = "verified";
    for (const r of this.#results.values()) {
      if (!r) {
        continue;
      }
      if (STATUS_PRIORITY[r.status] > STATUS_PRIORITY[worst]) {
        worst = r.status;
      }
    }
    switch (worst) {
      case "invalid":
      case "revoked":
      case "unknown":
        // `unknown` means the verifier completed but could not give a
        // definitive answer (unsupported subfilter, bridge error,
        // CMS NOT_YET_ATTEMPTED). Treat that as a verification failure
        // — the loading dots are reserved for the in-flight case
        // handled above.
        button.classList.add("state-error");
        break;
      case "expired":
      case "untrusted":
        button.classList.add("state-warn");
        break;
      default:
        button.classList.add("state-verified");
    }
  }
}

export { SignaturePropertiesManager };
