/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */

/**
 * Checks that key bytes have a type of Uint8Array and a specific length.
 *
 * @throws {TypeError|SyntaxError} - Throws a Type or Syntax error.
 *
 * @param {object} options - Options to use.
 * @param {Uint8Array} options.bytes - The bytes being checked.
 * @param {number} [options.expectedLength=32] - The expected bytes length.
 * @param {string} [options.code] - An optional code for the error.
 *
 * @returns {undefined} Returns on success throws on error.
 */
export const checkKeyBytes = ({bytes, expectedLength = 32, code}) => {
  if(!(bytes instanceof Uint8Array)) {
    throw new TypeError('"bytes" must be a Uint8Array.');
  }
  if(bytes.length !== expectedLength) {
    const error = new Error(
      `"bytes" must be a ${expectedLength}-byte Uint8Array.`);
    // we need DataError for invalid byte length
    error.name = 'DataError';
    // add the error code from the did:key spec if provided
    if(code) {
      error.code = code;
    }
    throw error;
  }
};
