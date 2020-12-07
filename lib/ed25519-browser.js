/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import * as ed25519 from '@stablelib/ed25519';
import {randomBytes as _randomBytes} from '@stablelib/random';

// used by stabelid to generate randomBytes
const randomBytes = () => _randomBytes(32);

export default {
  ...ed25519,
  async generateKeyPair() {
    return ed25519.generateKeyPair({randomBytes});
  }
};
