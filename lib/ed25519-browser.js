/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import * as ed25519 from '@stablelib/ed25519';
import {randomBytes} from '@stablelib/random';

export default {
  ...ed25519,
  async generateKeyPair() {
    return ed25519.generateKeyPair({randomBytes: () => randomBytes(32)});
  }
};
