const assert = require('node:assert/strict')
const fs = require('node:fs')
const test = require('node:test')
const { bindingName } = require('./loader')
const packageJson = require('./package.json')

const glibc = { getReport: () => ({ header: { glibcVersionRuntime: '2.39' } }) }
const musl = { getReport: () => ({ header: {} }) }

const packagedTargets = new Map([
  ['x86_64-unknown-linux-gnu', 'thorax.linux-x64-gnu.node'],
  ['aarch64-unknown-linux-gnu', 'thorax.linux-arm64-gnu.node'],
  ['x86_64-unknown-linux-musl', 'thorax.linux-x64-musl.node'],
  ['aarch64-unknown-linux-musl', 'thorax.linux-arm64-musl.node'],
  ['x86_64-apple-darwin', 'thorax.darwin-x64.node'],
  ['aarch64-apple-darwin', 'thorax.darwin-arm64.node'],
  ['x86_64-pc-windows-msvc', 'thorax.win32-x64-msvc.node'],
  ['aarch64-pc-windows-msvc', 'thorax.win32-arm64-msvc.node'],
])

test('declares every loader target in the published package', () => {
  assert.deepEqual(packageJson.napi.targets, [...packagedTargets.keys()])
})

test('selects the exact native artifact for every packaged target', () => {
  assert.equal(bindingName('linux', 'x64', glibc), 'thorax.linux-x64-gnu.node')
  assert.equal(bindingName('linux', 'x64', musl), 'thorax.linux-x64-musl.node')
  assert.equal(bindingName('linux', 'arm64', glibc), 'thorax.linux-arm64-gnu.node')
  assert.equal(bindingName('linux', 'arm64', musl), 'thorax.linux-arm64-musl.node')
  assert.equal(bindingName('darwin', 'x64'), 'thorax.darwin-x64.node')
  assert.equal(bindingName('darwin', 'arm64'), 'thorax.darwin-arm64.node')
  assert.equal(bindingName('win32', 'x64'), 'thorax.win32-x64-msvc.node')
  assert.equal(bindingName('win32', 'arm64'), 'thorax.win32-arm64-msvc.node')
})

test('rejects an unsupported platform instead of loading a foreign binary', () => {
  assert.throws(() => bindingName('freebsd', 'x64'), /Unsupported Thorax platform/)
})

test('release assembly contains every declared native artifact', {
  skip: process.env.THORAX_ASSERT_PACKAGED_BINDINGS !== '1',
}, () => {
  for (const artifact of packagedTargets.values()) {
    assert.ok(fs.existsSync(artifact), `missing packaged native artifact: ${artifact}`)
  }
})
