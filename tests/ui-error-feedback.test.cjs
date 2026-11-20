const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const view = name => fs.readFileSync(path.join(__dirname, '..', 'views', name), 'utf8');

function inlineScript(name) {
  const lines = view(name).split(/\r?\n/);
  const start = lines.findIndex(line => line.startsWith('<script ') && !line.includes(' src='));
  const end = lines.indexOf('</script>', start + 1);
  assert(start >= 0 && end > start, 'Missing inline script in ' + name);
  return lines.slice(start + 1, end).join('\n');
}

function element(properties = {}) {
  const listeners = {};
  const classes = new Set();
  return {
    style: {},
    classList: {
      contains: name => classes.has(name),
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle: (name, active) => active ? classes.add(name) : classes.delete(name),
    },
    addEventListener: (type, handler) => { listeners[type] = handler; },
    click: () => listeners.click(),
    ...properties,
  };
}

function reveal() {
  const nodes = {
    revealbutton: element(),
    revealarea: element(),
    passwordarea: element(),
    errorMessage: element(),
    csrfToken: element({ value: 'mock csrf' }),
    'password-text': element(),
  };
  const requests = [];
  const timers = [];
  const redirects = [];
  vm.runInNewContext(inlineScript('password.html'), {
    document: { getElementById: id => nodes[id] },
    window: { location: {
      protocol: 'https:', host: 'test.example', pathname: '/secret',
      href: 'https://test.example/secret', replace: target => redirects.push(target),
    } },
    XMLHttpRequest: class {
      constructor() { requests.push(this); }
      open(method, target) { Object.assign(this, { method, target }); }
      setRequestHeader() {}
      send(body) { this.body = body; }
    },
    setTimeout: (callback, delay) => timers.push({ callback, delay }),
  });
  return { nodes, requests, timers, redirects };
}

test('a transport failure announces a possible view and reloads without a second POST', () => {
  for (const event of ['onerror', 'onabort', 'ontimeout']) {
    const { nodes, requests, timers, redirects } = reveal();
    assert.match(view('password.html'), /id="errorMessage" role="alert"/);
    nodes.revealbutton.click();
    assert.equal(nodes.revealbutton.disabled, true);
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].body, '_csrf=mock%20csrf');
    requests[0][event]();
    nodes.revealbutton.click();
    assert.equal(requests.length, 1);
    assert.equal(nodes.errorMessage.textContent, '⚠️ The connection was interrupted. This attempt may have counted as a view.');
    assert.equal(nodes.errorMessage.classList.contains('text-warning'), true);
    assert.equal(nodes.errorMessage.classList.contains('d-inline-block'), true);
    assert.equal(nodes.errorMessage.classList.contains('py-2'), true);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].delay, 3000);
    timers[0].callback();
    assert.deepEqual(redirects, ['https://test.example/secret']);
  }
});

test('successful reveal shows the secret while HTTP errors retain their prior messages', () => {
  for (const [status, error] of [
    [200, null],
    [404, '🚫 Password was not found on this server'],
    [503, '🚫 A problem occurred while retrieving the password, please try again'],
  ]) {
    const { nodes, requests, timers } = reveal();
    nodes.revealbutton.click();
    Object.assign(requests[0], { status, responseText: 'test secret' });
    requests[0].onload();
    if (error) {
      assert.equal(nodes.errorMessage.textContent, error);
      assert.equal(nodes.errorMessage.classList.contains('text-warning'), false);
      assert.equal(nodes.errorMessage.classList.contains('py-2'), false);
      assert.equal(timers[0].delay, 3000);
    } else {
      assert.equal(nodes['password-text'].value, 'test secret');
      assert.equal(nodes.passwordarea.style.display, 'block');
      assert.equal(timers.length, 0);
    }
  }
});

function copy(clipboard, executeCopy) {
  const feedback = element();
  const legacyCalls = [];
  const targets = ['#file-link', '#password-link'];
  const buttons = targets.map(target => element({ dataset: { clipboardTarget: target } }));
  const fields = new Map(targets.map(target => [target, element({
    value: target,
    focus: () => legacyCalls.push('focus ' + target),
    select: () => legacyCalls.push('select ' + target),
  })]));
  vm.runInNewContext(inlineScript('clipboard_feedback.html'), {
    navigator: { clipboard },
    document: {
      querySelector: selector => selector === '[data-clipboard-feedback]' ? feedback : fields.get(selector),
      querySelectorAll: () => buttons,
      execCommand: command => {
        legacyCalls.push(command);
        return executeCopy();
      },
    },
  });
  return { feedback, buttons, legacyCalls };
}

test('copy rejection warns without navigation and another copy can clear the warning', async () => {
  const writes = [];
  const { feedback, buttons, legacyCalls } = copy({ async writeText(text) {
    writes.push(text);
    if (writes.length === 1) throw new Error('Clipboard permission denied');
  } });
  await buttons[0].click();
  assert.equal(feedback.textContent, '⚠️ Could not copy. Select and copy the text manually.');
  assert.equal(feedback.classList.contains('text-warning'), true);
  assert.equal(feedback.classList.contains('d-inline-block'), true);
  assert.equal(feedback.classList.contains('py-2'), true);
  await buttons[1].click();
  assert.equal(feedback.textContent, '');
  assert.equal(feedback.classList.contains('text-warning'), false);
  assert.equal(feedback.classList.contains('d-inline-block'), false);
  assert.equal(feedback.classList.contains('py-2'), false);
  assert.deepEqual(writes, ['#file-link', '#password-link']);
  assert.deepEqual(legacyCalls, []);
});

test('legacy copy checks success and leaves the selected text in place if refused', () => {
  let accepted = false;
  const { feedback, buttons, legacyCalls } = copy(undefined, () => accepted);
  buttons[0].click();
  assert.equal(feedback.textContent, '⚠️ Could not copy. Select and copy the text manually.');
  assert.deepEqual(legacyCalls, ['focus #file-link', 'select #file-link', 'copy']);
  accepted = true;
  buttons[1].click();
  assert.equal(feedback.textContent, '');
  assert.deepEqual(legacyCalls.slice(3), ['focus #password-link', 'select #password-link', 'copy']);
});

test('copy feedback is present on all three views', () => {
  for (const name of ['confirm.html', 'confirm_file.html', 'password.html']) {
    assert.match(view(name), /role="(?:status|alert)" data-clipboard-feedback/);
    assert.match(view(name), /include "clipboard_feedback\.html"/);
  }
  const file = view('confirm_file.html');
  assert.match(file, /id="copy-clipboard-btn" data-clipboard-target="#file-link"/);
  assert.match(file, /id="copy-password-clipboard-btn" data-clipboard-target="#password-link"/);
});
