# Duke Energy OAuth Helper

This optional Chrome extension captures Duke's iOS HTTPS callback and legacy Android `cma-prod://` callback. It also sends an iOS Safari User-Agent to `login.duke-energy.com`, following the workaround reported in [upstream PR 23](https://github.com/hunterjm/aiodukeenergy/pull/23) for desktop logins returning `access_denied`. It does not guarantee that every account or browser will authorize successfully.

## Install and use

Review `manifest.json`, `rules.json`, and the source before installing. In Chrome's `chrome://extensions/` page, enable Developer mode, choose **Load unpacked**, and select this folder. Follow your browser's extension policy; do not disable security controls.

Start a fresh sign-in from the application after enabling the helper. Complete Duke's login and any verification steps. The capture page displays a masked code on success or Duke's error text on failure.

- For [jameslb/ha-dukeenergy](https://github.com/jameslb/ha-dukeenergy)'s manual callback form, choose **Copy complete callback URL** and paste it into the same Home Assistant setup flow. This includes the transaction state that Home Assistant must validate.
- For `examples/browser_auth.py` or applications asking for a code only, use the copy icon beside the masked code.
- Legacy Home Assistant flows using a JWT state containing `flow_id` retain their existing automatic redirect behavior.

The complete-URL button appears only for a matching iOS callback with a nonempty state and no OAuth error. A URL containing `error=access_denied` has no usable authorization code; start a fresh login after addressing the failure.

## Permissions and privacy

The helper uses `webNavigation` and `tabs` to detect callback navigation. Its declarative request rule changes the User-Agent and removes Chromium client-hint headers only for `login.duke-energy.com`. Other domains are not included in that rule. There is no analytics or external callback-storage service.

Codes and callback URLs are sensitive, short-lived, and single-use. They are held in the local capture-page URL and copied to the clipboard only when selected. Close the capture tab and clear sensitive clipboard contents after use; do not share the URL or screenshots containing it. Disable or remove the helper when finished if desired.

## Local regression checks

Run `node --test chrome-extension/capture.test.cjs` from the repository root. These tests use synthetic data and browser API stubs; they do not install the extension or log in to Duke.
