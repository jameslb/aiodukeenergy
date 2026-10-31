// Synthetic browser API stubs; no real login, browser, or clipboard access.
const { test } = require("node:test");
const assert = require("node:assert/strict");

const callback =
  "https://login.duke-energy.com/ios/com.duke-energy.app/callback?code=synthetic-code&state=synthetic-state";

test("mobile request rule is restricted to Duke login", () => {
  const rules = require("./rules.json");
  assert.equal(rules.length, 1);
  assert.deepEqual(rules[0].condition.requestDomains, [
    "login.duke-energy.com",
  ]);
  assert.equal(rules[0].action.type, "modifyHeaders");
  assert(
    rules[0].action.requestHeaders.some(
      (header) =>
        header.header.toLowerCase() === "user-agent" &&
        header.operation === "set" &&
        header.value.includes("iPhone"),
    ),
  );
});

test("background forwards the original full callback to the capture page", () => {
  let updated, onUpdated;
  global.chrome = {
    runtime: { getURL: (path) => `chrome-extension://synthetic/${path}` },
    tabs: {
      update(tabId, data) {
        updated = { tabId, ...data };
      },
      onUpdated: {
        addListener(handler) {
          onUpdated = handler;
        },
      },
    },
    action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
    webNavigation: {
      onBeforeNavigate: { addListener() {} },
      onErrorOccurred: { addListener() {} },
    },
  };
  require("./background.js");
  onUpdated(7, { url: callback });
  assert.equal(updated.tabId, 7);
  const params = new URL(updated.url).searchParams;
  assert.equal(params.get("callback_url"), callback);
  assert.equal(params.get("state"), "synthetic-state");
});

function loadCapture(url, extra = {}) {
  const nodes = new Map();
  const copied = [];
  global.window = {
    location: {
      search: `?${new URLSearchParams({
        code: "synthetic-code",
        state: "synthetic-state",
        callback_url: url,
        ...extra,
      })}`,
    },
  };
  global.document = {
    getElementById(id) {
      if (!nodes.has(id))
        nodes.set(id, {
          style: {},
          textContent: "",
          handlers: {},
          addEventListener(event, handler) {
            this.handlers[event] = handler;
          },
          classList: { add() {}, remove() {} },
        });
      return nodes.get(id);
    },
  };
  Object.defineProperty(global, "navigator", {
    configurable: true,
    value: {
      clipboard: {
        async writeText(value) {
          copied.push(value);
        },
      },
    },
  });
  delete require.cache[require.resolve("./capture.js")];
  require("./capture.js");
  return { nodes, copied };
}

test("copies complete callback with state while masking the visible code", async () => {
  const { nodes, copied } = loadCapture(callback);
  assert.equal(nodes.get("callbackSection").style.display, "block");
  assert(!nodes.get("authCode").textContent.includes("synthetic-code"));
  await nodes.get("copyCallback").handlers.click();
  assert.deepEqual(copied, [callback]);
});

for (const invalid of [
  "invalid",
  callback.replace("login.duke-energy.com", "example.com"),
  callback.replace("&state=synthetic-state", ""),
  callback.replace("synthetic-code", "different"),
  callback.replace("synthetic-state", "different"),
  `${callback}&error=access_denied`,
]) {
  test(`does not offer an invalid callback: ${invalid}`, () => {
    const { nodes } = loadCapture(invalid);
    assert.equal(nodes.has("copyCallback"), false);
  });
}

test("renders OAuth errors as text without claiming success", () => {
  const { nodes } = loadCapture("", {
    code: "",
    error: "access_denied",
    error_description: "<script>synthetic</script>",
  });
  assert.equal(nodes.get("noCode").style.display, "block");
  assert.equal(nodes.has("success"), false);
  assert.equal(
    nodes.get("errorDetail").textContent,
    "access_denied: <script>synthetic</script>",
  );
});
