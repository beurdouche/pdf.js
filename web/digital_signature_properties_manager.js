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

import { AnnotationEditorType, makeArr, PDFDateString } from "pdfjs-lib";

// Per-status descriptor keyed by the status code returned by the verifier.
// `priority` drives worst-status aggregation, `severity` drives the banner
// colour bucket, and the two Fluent IDs are the explicit strings used by
// the banner / status rows (no `${status}` template construction so the
// IDs are greppable).
// The status row only ever shows one of three distinct strings: the
// signature crypto verified, the signature is invalid, or the format is
// unsupported. Cert chain issues (untrusted / expired / revoked) live
// on the cert row, so those statuses still report "Signature verified"
// on the status row.
const STATUS_ROW_VERIFIED =
  "pdfjs-digital-signature-properties-status-verified";
const STATUS_ROW_INVALID = "pdfjs-digital-signature-properties-status-invalid";
const STATUS_ROW_UNKNOWN = "pdfjs-digital-signature-properties-status-unknown";

const STATUS_INFO = {
  verified: {
    priority: 0,
    severity: "verified",
    bannerId: "pdfjs-digital-signature-properties-banner-verified",
    statusId: STATUS_ROW_VERIFIED,
  },
  unknown: {
    priority: 1,
    severity: "error",
    bannerId: "pdfjs-digital-signature-properties-banner-unknown",
    statusId: STATUS_ROW_UNKNOWN,
  },
  untrusted: {
    priority: 2,
    severity: "warn",
    bannerId: "pdfjs-digital-signature-properties-banner-untrusted",
    statusId: STATUS_ROW_VERIFIED,
  },
  expired: {
    priority: 3,
    severity: "warn",
    bannerId: "pdfjs-digital-signature-properties-banner-expired",
    statusId: STATUS_ROW_VERIFIED,
  },
  revoked: {
    priority: 4,
    severity: "error",
    bannerId: "pdfjs-digital-signature-properties-banner-revoked",
    statusId: STATUS_ROW_VERIFIED,
  },
  invalid: {
    priority: 5,
    severity: "error",
    bannerId: "pdfjs-digital-signature-properties-banner-invalid",
    statusId: STATUS_ROW_INVALID,
  },
};

const CERT_L10N_IDS = {
  trusted: "pdfjs-digital-signature-properties-certificate-trusted",
  unknown: "pdfjs-digital-signature-properties-certificate-unknown",
  untrusted: "pdfjs-digital-signature-properties-certificate-untrusted",
  expired: "pdfjs-digital-signature-properties-certificate-expired",
  revoked: "pdfjs-digital-signature-properties-certificate-revoked",
};

const CERT_EXPIRED_WITH_DATE_L10N_ID =
  "pdfjs-digital-signature-properties-certificate-expired-with-date";

// Shown instead of the per-status banner when the signatures verified but
// the document contains content none of them covers, and on the card of
// the top-level signature that falls short.
const BANNER_MODIFIED = "pdfjs-digital-signature-properties-banner-modified";
const COVERAGE_PARTIAL_L10N_ID =
  "pdfjs-digital-signature-properties-coverage-partial";

// For an `untrusted` certificate, pick the most specific Fluent label.
// When the error code matches one of the recognised cases we have a
// structured "Certificate: <reason> (<issuer>)" string; otherwise we
// fall back to the bare "Certificate: Untrusted".
function untrustedCertLabel(errorCode, issuerCN) {
  const code = (errorCode || "").toUpperCase();
  const args = issuerCN ? { issuer: issuerCN } : null;
  if (code.includes("UNKNOWN_ISSUER") && args) {
    return {
      id: "pdfjs-digital-signature-properties-certificate-untrusted-unknown-issuer",
      args,
    };
  }
  if (code.includes("SELF_SIGNED") && args) {
    return {
      id: "pdfjs-digital-signature-properties-certificate-untrusted-self-signed",
      args,
    };
  }
  if (code.includes("UNTRUSTED_ISSUER") && args) {
    return {
      id: "pdfjs-digital-signature-properties-certificate-untrusted-untrusted-issuer",
      args,
    };
  }
  return {
    id: "pdfjs-digital-signature-properties-certificate-untrusted",
    args: null,
  };
}

// For an `expired` certificate: NSS may have flagged either the leaf
// (SEC_ERROR_EXPIRED_CERTIFICATE) or any issuer up the chain
// (SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE). We want the parenthetical
// to show the date that actually expired, so walk leaf + chain and
// return the first notAfter that is already in the past as a Date.
// If nothing is in the past we return null and the caller renders the
// generic "Certificate: Expired" label without a date.
function expirationDateForCert(cert) {
  if (!cert) {
    return null;
  }
  const now = Date.now();
  const entries =
    Array.isArray(cert.chain) && cert.chain.length ? cert.chain : [cert];
  // Return the first past notAfter in the chain — that's the cert that
  // actually caused the "expired" verdict. We deliberately do NOT fall
  // back to a future date if no past date is found: NSS sometimes does
  // not surface the expired issuer in `signerCertificate.issuer`, in
  // which case the chain only has the leaf with a still-valid notAfter.
  // Showing that as "Expired (Jan 1, 2027)" would be misleading, so the
  // caller renders the dateless label instead.
  for (const entry of entries) {
    if (typeof entry?.notAfter !== "string" || !entry.notAfter) {
      continue;
    }
    const date = new Date(entry.notAfter);
    const ts = date.getTime();
    if (Number.isFinite(ts) && ts < now) {
      return date;
    }
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

  // Set whenever state changes while the panel is closed, so that opening it
  // forces a fresh render. While the panel is hidden, building the list /
  // banner DOM is pure churn — only the toolbar button is visible, and that
  // is updated via #updateButtonState().
  #needsRender = false;

  #pdfDocument = null;

  constructor({ appConfig, verifier, eventBus }) {
    this.#appConfig = appConfig;
    this.#verifier = verifier;
    this.#eventBus = eventBus;

    const button = appConfig.signaturePropertiesButton;
    // Loading dots: three real spans (hidden by `.toolbarButton > span`)
    // that the `state-loading` CSS modifier turns into pulsing circles
    // with staggered `animation-delay`. Real elements (not gradient
    // keyframes) let each dot animate independently.
    for (let i = 0; i < 3; i++) {
      const dot = document.createElement("span");
      dot.className = "loadingDot";
      button.append(dot);
    }
    button.addEventListener("click", () => {
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

  async setDocument(pdfDocument) {
    if (this.#pdfDocument) {
      this.#signatures = [];
      this.#results.clear();
      this.#pendingVerify.clear();
      this.#needsRender = false;
      this.#hideButton();
      this.#close();
      this.#updateButtonState();
    }
    this.#pdfDocument = pdfDocument;

    if (!pdfDocument) {
      return;
    }
    this.#isLoading = true;
    this.#render();

    let signatures;
    try {
      signatures = await pdfDocument.getSignatures();
    } catch (ex) {
      console.warn("getSignatures failed:", ex);
    }
    if (pdfDocument !== this.#pdfDocument) {
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
        status: "unknown",
        errorCode: null,
        message: null,
        certificate: null,
      });
    }
    this.#render();
    this.#updateButtonState();
    // Kick off verification automatically — the toolbar button reflects the
    // aggregate state and updates as each signature resolves.
    for (const sig of this.#signatures) {
      this.#verify(sig, pdfDocument);
    }
  }

  #showButton() {
    const root = this.#appConfig.signaturePropertiesButton.parentElement;
    if (root) {
      root.hidden = false;
    }
    // The separator only makes sense when our toolbar group is visible.
    const sep = this.#appConfig.signaturePropertiesSeparator;
    if (sep) {
      sep.hidden = false;
    }
  }

  #hideButton() {
    const root = this.#appConfig.signaturePropertiesButton.parentElement;
    if (root) {
      root.hidden = true;
    }
    const sep = this.#appConfig.signaturePropertiesSeparator;
    if (sep) {
      sep.hidden = true;
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
    if (this.#needsRender) {
      this.#render();
    }
  }

  #close() {
    this.#isOpen = false;
    this.#appConfig.signaturePropertiesPanel.classList.add("hidden");
    this.#appConfig.signaturePropertiesButton.setAttribute(
      "aria-expanded",
      "false"
    );
  }

  get #worst() {
    let worst = "verified";
    for (const r of this.#results.values()) {
      if (
        r?.status &&
        STATUS_INFO[r.status].priority > STATUS_INFO[worst].priority
      ) {
        worst = r.status;
      }
    }
    return worst;
  }

  // Whether the document contains content that no signature covers —
  // typically an incremental update appended after signing.
  //
  // Only *top-level* signatures are consulted. Every inner signature in a
  // legitimately multi-signed document stops short of the file end, since
  // later revisions were appended on top of it; flagging those would fire
  // on every multi-signature PDF. A top-level signature (`parentId ===
  // null`) is the revision that's supposed to cover the current document
  // state, so it falling short is what actually means "unsigned changes".
  get #hasUnsignedChanges() {
    return this.#signatures.some(s => !s.parentId && !s.coversWholeDocument);
  }

  get #bannerState() {
    if (this.#results.size === 0) {
      return {
        severity: "error",
        bannerId: STATUS_INFO.unknown.bannerId,
        count: 0,
      };
    }
    const worst = this.#worst;
    let count = 0;
    // Count how many signatures are at the worst level — this drives the
    // singular/plural variant of the banner message.
    for (const r of this.#results.values()) {
      if (r?.status === worst) {
        count++;
      }
    }
    let { severity, bannerId } = STATUS_INFO[worst];
    // Unsigned changes must never *hide* a verification failure, so only
    // take over the headline when the signatures themselves are fine —
    // which is exactly the misleading case: a valid signature that says
    // nothing about the content appended after it. When something did
    // fail, its more specific banner wins and the per-signature coverage
    // row still reports the unsigned changes.
    if (severity === "verified" && this.#hasUnsignedChanges) {
      severity = "warn";
      bannerId = BANNER_MODIFIED;
    }
    return { severity, bannerId, count };
  }

  #render() {
    if (!this.#isOpen) {
      // Defer DOM work until the user actually opens the panel.
      this.#needsRender = true;
      return;
    }
    this.#needsRender = false;
    const list = this.#appConfig.signaturePropertiesList;
    const banner = this.#appConfig.signaturePropertiesBanner;
    const fragment = document.createDocumentFragment();

    if (this.#isLoading) {
      // The worker call that populates `#signatures` resolves in tens of
      // milliseconds — fast enough that we'd rather show nothing than
      // flash a placeholder. The toolbar button's loading-dot animation
      // already conveys "work in progress".
      banner.hidden = true;
      list.replaceChildren();
      return;
    }

    // Banner.
    const { severity, bannerId, count } = this.#bannerState;
    banner.replaceChildren();
    banner.hidden = false;
    banner.className = `sigBanner ${severity}`;
    banner.setAttribute("data-l10n-id", bannerId);
    banner.setAttribute("data-l10n-args", JSON.stringify({ count }));

    // Group sub-signatures under their parent.
    const byParent = new Map();
    const topLevel = [];
    for (const sig of this.#signatures) {
      if (sig.parentId) {
        byParent.getOrInsertComputed(sig.parentId, makeArr).push(sig);
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
      fragment.append(
        this.#renderCard(sig, byParent, /* depth = */ 0, everythingFine)
      );
    }
    list.replaceChildren(fragment);
  }

  #renderCard(sig, byParent, depth, everythingFine) {
    const subs = byParent.get(sig.id) || [];
    const li = document.createElement("li");
    li.classList.add("sigCard");
    if (depth === 0 && everythingFine) {
      li.classList.add("sigCard--top-allfine");
    }

    const result = this.#results.get(sig.id);

    const subjectCN = result?.certificate?.subjectCN;
    if (subjectCN) {
      const signer = document.createElement("div");
      signer.className = "signer";
      signer.textContent = subjectCN;
      li.append(signer);
    }

    // Status row.
    const statusRow = document.createElement("div");
    statusRow.classList.add("row", `status--${result.status}`);
    const statusLabel = document.createElement("span");
    statusLabel.setAttribute(
      "data-l10n-id",
      STATUS_INFO[result.status].statusId
    );
    statusRow.append(statusLabel);
    li.append(statusRow);

    if (result.status === "invalid" && result.message) {
      const reason = document.createElement("div");
      reason.className = "detail";
      reason.setAttribute(
        "data-l10n-id",
        "pdfjs-digital-signature-properties-reason"
      );
      reason.setAttribute(
        "data-l10n-args",
        JSON.stringify({ reason: result.message })
      );
      li.append(reason);
    }

    // Certificate row — skipped when the signature itself is invalid:
    // NSS doesn't return a signerCertificate in that case, so the row
    // would be empty noise next to the more informative "Reason: …"
    // line.
    const cert = result.certificate;
    let certKind = "unknown";
    if (cert) {
      switch (result.status) {
        case "verified":
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
    if (result.status !== "invalid") {
      const certRow = document.createElement("div");
      certRow.classList.add("row", `cert--${certKind}`);
      const certLabel = document.createElement("span");
      let l10nId = CERT_L10N_IDS[certKind];
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
          l10nId = CERT_EXPIRED_WITH_DATE_L10N_ID;
          l10nArgs = { dateObj: date.valueOf() };
        }
      } else if (certKind === "untrusted") {
        const label = untrustedCertLabel(result.errorCode, cert?.issuerCN);
        l10nId = label.id;
        l10nArgs = label.args;
      }
      certLabel.setAttribute("data-l10n-id", l10nId);
      if (l10nArgs) {
        certLabel.setAttribute("data-l10n-args", JSON.stringify(l10nArgs));
      }
      certRow.append(certLabel);
      li.append(certRow);
    }

    // Coverage row — only for a top-level signature, since inner ones
    // always stop short of the file end by design (see `#hasUnsignedChanges`).
    if (depth === 0 && !sig.coversWholeDocument) {
      const coverageRow = document.createElement("div");
      coverageRow.classList.add("row", "coverage--partial");
      const coverageLabel = document.createElement("span");
      coverageLabel.setAttribute("data-l10n-id", COVERAGE_PARTIAL_L10N_ID);
      coverageRow.append(coverageLabel);
      li.append(coverageRow);
    }

    if (result.status === "untrusted" && result.message) {
      const detail = document.createElement("div");
      detail.className = "detail";
      detail.textContent = result.message;
      li.append(detail);
    }
    if (result.status === "expired" && result.message) {
      const detail = document.createElement("div");
      detail.className = "detail";
      detail.textContent = result.message;
      li.append(detail);
    }

    const signingDate = PDFDateString.toDateObject(sig.signingTime);
    if (signingDate) {
      const ts = document.createElement("div");
      ts.className = "detail";
      ts.setAttribute(
        "data-l10n-id",
        "pdfjs-digital-signature-properties-timestamp"
      );
      ts.setAttribute(
        "data-l10n-args",
        JSON.stringify({ dateObj: signingDate.valueOf() })
      );
      li.append(ts);
    }

    if (cert && typeof this.#verifier?.viewCertificate === "function") {
      const viewCert = document.createElement("button");
      viewCert.className = "viewCert";
      viewCert.type = "button";
      viewCert.setAttribute(
        "data-l10n-id",
        "pdfjs-digital-signature-properties-view-certificate"
      );
      viewCert.addEventListener("click", e => {
        e.stopPropagation();
        this.#verifier.viewCertificate(cert);
      });
      li.append(viewCert);
    }

    if (subs.length > 0) {
      const subList = document.createElement("ul");
      subList.classList.add("signaturePropertiesList", "nested");
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
        details.className = "subSignatures";
        details.open = true;
        const summary = document.createElement("summary");
        summary.setAttribute(
          "data-l10n-id",
          "pdfjs-digital-signature-properties-sub-signatures"
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

    // Note: per-card progress is already conveyed via the toolbar
    // button's loading-dot animation (state-loading class) — we used to
    // drop an additional pulsing bar at the bottom of each in-flight
    // card but it was visual noise without clear meaning.

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

  async #verify(signature, pdfDocument) {
    if (!this.#verifier || this.#pendingVerify.has(signature.id)) {
      return;
    }
    this.#pendingVerify.add(signature.id);
    this.#render();

    let result;
    try {
      // Fetch the signature's byte payload (pkcs7 + signed-data spans)
      // lazily, one signature at a time, so the bytes never sit in main
      // thread memory for the document's lifetime. `bytes` goes out of
      // scope as soon as the verifier returns.
      const bytes = await pdfDocument.getSignatureData(signature.id);
      if (pdfDocument !== this.#pdfDocument) {
        return;
      }
      if (!bytes) {
        throw new Error("missing signature data");
      }
      result = await this.#verifier.verify({ ...signature, ...bytes });
    } catch (ex) {
      console.warn("signature verify failed:", ex);
      result = {
        status: "unknown",
        errorCode: "BRIDGE_ERROR",
        message: ex?.message ?? null,
        certificate: null,
      };
    }
    this.#pendingVerify.delete(signature.id);
    if (pdfDocument !== this.#pdfDocument) {
      // The user switched documents while this verify was in flight; the
      // result belongs to a defunct load and would corrupt the new doc.
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
    // The `severity` buckets are named to match the `state-*` modifiers,
    // so the banner and the toolbar icon can never disagree. Note that
    // `unknown` maps to `error`: the verifier completed but could not give
    // a definitive answer (unsupported subfilter, bridge error, CMS
    // NOT_YET_ATTEMPTED), which is a verification failure — the loading
    // dots are reserved for the in-flight case handled above.
    const { severity } = this.#bannerState;
    button.classList.add(`state-${severity}`);
  }
}

export { SignaturePropertiesManager };
