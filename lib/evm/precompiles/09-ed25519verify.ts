import BN = require('bn.js')
import ed25519 = require('ed25519');
import { PrecompileInput } from './types'
import { OOGResult, ExecResult } from '../evm'
const assert = require('assert')

export default function(opts: PrecompileInput): ExecResult {
  assert(opts.data)

  const inputData = opts.data
  // Parse input data (data is a Buffer)
  // The first 32 bytes represent the message
  var message = data.slice(0, 32)

  // The next 32 bytes represent the public key
  var pubKey = data.slice(32, 64)

  // The final 64 bytes represent the signature
  var signature = data.slice(64, 128)

  // Normally, the gas cost comes from
  // here: https://github.com/ethereumjs/ethereumjs-common/blob/master/src/hardforks/byzantium.json
  // enable to compute the gas cost of a precompiled call
  //
  // We hard code an arbitrary value for the added precompiled. For testing purposes only!
  const gasUsed = new BN(2000)

  if (opts.gasLimit.lt(gasUsed)) {
    return OOGResult(opts.gasLimit)
  }

  const returnData = ed25519.Verify(message, signature, pubKey)

  // check ecpairing success or failure by comparing the output length
  if (returnData.length !== 32) {
    return OOGResult(opts.gasLimit)
  }

  return {
    gasUsed,
    returnValue: returnData,
  }
}
