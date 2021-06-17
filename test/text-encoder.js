/*
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
function stringToUint8Array(data) {
  if(typeof data === 'string') {
    // convert data to Uint8Array
    return new TextEncoder().encode(data);
  }
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" be a string or Uint8Array.');
  }
  return data;
}

module.exports = {
  stringToUint8Array
};
