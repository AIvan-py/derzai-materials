/* Чистый JS для старых Safari: SHA-256, HMAC, PBKDF2. Ключ 32 байта. ES5. */
var DerzaiCrypto = (function () {
  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function sha256(msg) { // msg: Uint8Array -> Uint8Array(32)
    var l = msg.length, bitLen = l * 8;
    var padLen = ((l + 9 + 63) >> 6) << 6;
    var m = new Uint8Array(padLen); m.set(msg); m[l] = 0x80;
    m[padLen - 4] = (bitLen >>> 24) & 255; m[padLen - 3] = (bitLen >>> 16) & 255; m[padLen - 2] = (bitLen >>> 8) & 255; m[padLen - 1] = bitLen & 255;
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    var w = new Array(64);
    for (var off = 0; off < padLen; off += 64) {
      for (var i = 0; i < 16; i++) { var j = off + i * 4; w[i] = (m[j] << 24) | (m[j+1] << 16) | (m[j+2] << 8) | m[j+3]; }
      for (i = 16; i < 64; i++) {
        var x = w[i-15], y = w[i-2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
      }
      var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + w[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
    }
    var out = new Uint8Array(32), hs = [h0,h1,h2,h3,h4,h5,h6,h7];
    for (i = 0; i < 8; i++) { out[i*4] = (hs[i] >>> 24) & 255; out[i*4+1] = (hs[i] >>> 16) & 255; out[i*4+2] = (hs[i] >>> 8) & 255; out[i*4+3] = hs[i] & 255; }
    return out;
  }
  function concat(a, b) { var r = new Uint8Array(a.length + b.length); r.set(a); r.set(b, a.length); return r; }
  function hmac(key, msg) {
    if (key.length > 64) key = sha256(key);
    var ipad = new Uint8Array(64), opad = new Uint8Array(64);
    for (var i = 0; i < 64; i++) { var k = i < key.length ? key[i] : 0; ipad[i] = k ^ 0x36; opad[i] = k ^ 0x5c; }
    return sha256(concat(opad, sha256(concat(ipad, msg))));
  }
  function pbkdf2(pw, salt, iter, len) { // len <= 32 здесь
    var u = hmac(pw, concat(salt, new Uint8Array([0,0,0,1]))), t = new Uint8Array(u);
    for (var i = 1; i < iter; i++) { u = hmac(pw, u); for (var j = 0; j < 32; j++) t[j] ^= u[j]; }
    return t.subarray(0, len);
  }
  function utf8(str) { var s = unescape(encodeURIComponent(str)), u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
  function fromB64(s) { var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
  function hex(u) { var s = ''; for (var i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16); return s; }
  function unhex(s) { var u = new Uint8Array(s.length / 2); for (var i = 0; i < u.length; i++) u[i] = parseInt(s.substr(i * 2, 2), 16); return u; }
  return { sha256: sha256, hmac: hmac, pbkdf2: pbkdf2, utf8: utf8, fromB64: fromB64, hex: hex, unhex: unhex };
})();
if (typeof module !== 'undefined') module.exports = DerzaiCrypto;
