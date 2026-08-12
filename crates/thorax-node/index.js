// Load exactly the native addon for this process. Requiring the first file that happens to
// exist makes an all-platform package abort on the Linux x64 binary on every other platform.
const { join } = require('path')
const { bindingName } = require('./loader')

const name = bindingName(process.platform, process.arch, process.report)
try {
  module.exports = require(join(__dirname, name))
} catch (error) {
  error.message = `Failed to load Thorax native binding ${name}: ${error.message}`
  throw error
}
