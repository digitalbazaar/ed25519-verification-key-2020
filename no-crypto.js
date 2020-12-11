// browser MUST provide "crypto.getRandomValues"
const crypto = self && (self.crypto || self.msCrypto);
if(!crypto.getRandomValues) {
  throw new Error('Browser does not provide "crypto.getRandomValues".');
}

export default crypto;
