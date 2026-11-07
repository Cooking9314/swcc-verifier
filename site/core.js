/* SWCC · ядро разбора .swcc. Чистые функции без DOM: печать файла,
   строгий base64, извлечение payload и порядок проверок.

   Единственный источник истины по формату — src/swcc.rs; формулировки отказов
   здесь дословные его копии. Тот же код гоняет .scratch/test-core.mjs в Node vm,
   поэтому менять его надо вместе с тестом и с Rust.

   Печать доказывает только целостность файла, а не авторство: соль лежит
   в программе у игрока. Об этом сказано в самом отчёте. */

(function (global) {
  'use strict';

  var WIDTH = 72;
  var PAYLOAD_START = '!PAYLOAD-BEGIN!';
  var PAYLOAD_END = '!PAYLOAD-END!';
  var SEAL_MARKER = '!SEAL!';
  var SEAL_SALT = 'sunrise-worlds-swcc-seal-v1';

  // Формулировки отказов — дословно как в Report::verify (src/swcc.rs),
  // чтобы консоль, GUI и эта страница не противоречили друг другу.
  var MSG = {
    noBegin: 'В файле нет машиночитаемой части: это не .swcc или файл обрезан.',
    noEnd: 'Конец payload не найден: файл повреждён или пересобран вручную.',
    badBase64: 'payload не декодируется: файл изменён после формирования.',
    badJsonPrefix: 'payload не разобран: ',
    noSeal: 'Печать в файле отсутствует.',
    sealMismatch: function (found, expected) {
      return 'Печать не сходится: в файле ' + found + ', пересчитано ' + expected +
        '. Текст payload изменён.';
    },
    intact: function (id, verdictRu) {
      return 'Целостность подтверждена. Отчёт ' + id + ' не редактирован (заключение: ' + verdictRu + ').';
    }
  };

  var B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var B64_LOOKUP = new Int8Array(256).fill(-1);
  for (var bi = 0; bi < 64; bi++) B64_LOOKUP[B64_ALPHABET.charCodeAt(bi)] = bi;
  var B64_PAD = 61; // '='

  var HEX_DIGITS = '0123456789abcdef';

  function toHex(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      out += HEX_DIGITS[(bytes[i] >> 4) & 15] + HEX_DIGITS[bytes[i] & 15];
    }
    return out;
  }

  // Rust удаляет из payload всё, что char::is_whitespace(). JS-\s почти совпадает,
  // но не знает U+0085; добавляем его, чтобы разбиение не зависело от переносов строк.
  var WHITESPACE_RE = /[\s\u0085]/g;
  function stripWhitespace(s) { return s.replace(WHITESPACE_RE, ''); }
  function stripBom(s) { return s.replace(/^\uFEFF+/, ''); }

  // --- SHA-256: резервная реализация на случай, когда crypto.subtle недоступен ---
  var SHA_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function sha256Local(bytes) {
    var rotr = function (x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; };
    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    var h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    var len = bytes.length;
    var total = ((len + 9 + 63) >> 6) << 6;
    var p = new Uint8Array(total);
    p.set(bytes);
    p[len] = 0x80;
    var dv = new DataView(p.buffer);
    dv.setUint32(total - 8, Math.floor(len / 0x20000000), false);
    dv.setUint32(total - 4, (len << 3) >>> 0, false);
    var w = new Uint32Array(64);
    for (var off = 0; off < total; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + SHA_K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    var out = new Uint8Array(32);
    var odv = new DataView(out.buffer);
    var hs = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (var k = 0; k < 8; k++) odv.setUint32(k * 4, hs[k], false);
    return out;
  }

  function subtleAvailable() {
    try {
      return !!(global.crypto && global.crypto.subtle &&
        typeof global.crypto.subtle.digest === 'function');
    } catch (e) {
      return false;
    }
  }

  function sha256(bytes) {
    if (subtleAvailable()) {
      try {
        var view = bytes.slice();
        return global.crypto.subtle.digest('SHA-256', view.buffer).then(function (buf) {
          return new Uint8Array(buf);
        });
      } catch (e) {
        return Promise.resolve(sha256Local(bytes));
      }
    }
    return Promise.resolve(sha256Local(bytes));
  }

  function concatBytes() {
    var parts = Array.prototype.slice.call(arguments);
    var n = 0;
    for (var i = 0; i < parts.length; i++) n += parts[i].length;
    var out = new Uint8Array(n), o = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
    return out;
  }

  // seal = hex(SHA-256(salt + payload))[0..12] — первые 12 байт digest, 24 hex.
  function sealFromDigest(digest) { return toHex(digest.subarray(0, 12)); }

  function sealFor(payload, localOnly) {
    var enc = new TextEncoder();
    var joined = concatBytes(enc.encode(SEAL_SALT), enc.encode(payload));
    if (localOnly) return Promise.resolve(sealFromDigest(sha256Local(joined)));
    return sha256(joined).then(sealFromDigest);
  }

  function decodeBase64Strict(s) {
    if (!s || s.length % 4 !== 0) return null;
    var end = s.length, pad = 0;
    if (s.charCodeAt(end - 1) === B64_PAD) {
      pad = 1;
      if (s.charCodeAt(end - 2) === B64_PAD) pad = 2;
    }
    var body = end - pad;
    if (body % 4 === 1) return null; // оборванный квартет: Rust тоже не декодирует
    var acc = 0, bits = 0, outLen = Math.floor((body * 3) / 4);
    var out = new Uint8Array(outLen), o = 0;
    for (var i = 0; i < body; i++) {
      var v = B64_LOOKUP[s.charCodeAt(i) & 255];
      if (v < 0) return null;
      acc = (acc << 6) | v;
      bits += 6;
      if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 255; }
    }
    return o === out.length ? out : out.subarray(0, o);
  }

  // Семантика извлечения payload как в Rust: всё между маркерами, все пробелы вон.
  function locate(text) {
    var body = stripBom(text);
    var start = body.indexOf(PAYLOAD_START);
    if (start < 0) return { body: body, payload: null, reason: 'no_begin' };
    var after = body.slice(start + PAYLOAD_START.length);
    var stop = after.indexOf(PAYLOAD_END);
    if (stop < 0) return { body: body, payload: null, reason: 'no_end' };
    return { body: body, payload: stripWhitespace(after.slice(0, stop)), reason: null };
  }

  // Как Rust: последний маркер !SEAL!, первое непробельное слово после него.
  function sealInFile(body) {
    var i = body.lastIndexOf(SEAL_MARKER);
    if (i < 0) return '';
    var rest = body.slice(i + SEAL_MARKER.length);
    var m = /\S+/.exec(rest);
    return m ? m[0] : '';
  }

  function jsonFromBytes(bytes) {
    var text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (e) {
      return { ok: false, error: 'payload не является UTF-8' };
    }
    try {
      return { ok: true, value: JSON.parse(text), text: text };
    } catch (e2) {
      return { ok: false, error: String(e2 && e2.message ? e2.message : e2), text: text };
    }
  }

  /**
   * verifyText(text, formatVerdict) -> Promise<outcome>
   * outcome: { intact, kind, detail, payload, payloadBytes, rawJsonText, fileSeal,
   *            expectedSeal, report, body, bytes, hashEngine }
   * kind: intact | tampered | no_seal | no_payload | no_payload_end | bad_base64 | bad_json
   */
  function verifyText(text, formatVerdict, localOnly) {
    var base = {
      intact: false, kind: '', detail: '', payload: null, payloadBytes: null,
      rawJsonText: null, fileSeal: '', expectedSeal: '', report: null, body: '', bytes: null
    };
    var loc = locate(text);
    base.body = loc.body;
    if (loc.reason === 'no_begin') {
      base.kind = 'no_payload'; base.detail = MSG.noBegin;
      return Promise.resolve(base);
    }
    if (loc.reason === 'no_end') {
      base.kind = 'no_payload_end'; base.detail = MSG.noEnd;
      return Promise.resolve(base);
    }
    base.payload = loc.payload;
    base.bytes = decodeBase64Strict(loc.payload);
    if (!base.bytes) {
      base.kind = 'bad_base64'; base.detail = MSG.badBase64;
      return Promise.resolve(base);
    }
    var parsed = jsonFromBytes(base.bytes);
    if (!parsed.ok) {
      base.kind = 'bad_json';
      base.detail = MSG.badJsonPrefix + parsed.error;
      base.rawJsonText = parsed.text || null;
      return Promise.resolve(base);
    }
    base.report = parsed.value;
    base.rawJsonText = parsed.text;
    base.fileSeal = sealInFile(loc.body);

    return sealFor(loc.payload, localOnly).then(function (expected) {
      base.expectedSeal = expected;
      base.hashEngine = localOnly ? 'local-sha256' : (subtleAvailable() ? 'webcrypto' : 'local-sha256');
      if (!base.fileSeal) {
        base.kind = 'no_seal'; base.detail = MSG.noSeal;
        return base;
      }
      if (base.fileSeal !== expected) {
        base.kind = 'tampered';
        base.detail = MSG.sealMismatch(base.fileSeal, expected);
        return base;
      }
      var ru = formatVerdict ? formatVerdict(base.report) : '';
      base.intact = true;
      base.kind = 'intact';
      base.detail = MSG.intact(base.report.id, ru);
      return base;
    });
  }

  global.SWCC_CORE = {
    WIDTH: WIDTH,
    PAYLOAD_START: PAYLOAD_START,
    PAYLOAD_END: PAYLOAD_END,
    SEAL_MARKER: SEAL_MARKER,
    SEAL_SALT: SEAL_SALT,
    MSG: MSG,
    stripBom: stripBom,
    stripWhitespace: stripWhitespace,
    toHex: toHex,
    sha256Local: sha256Local,
    sha256: sha256,
    sealFor: sealFor,
    sealFromDigest: sealFromDigest,
    subtleAvailable: subtleAvailable,
    decodeBase64Strict: decodeBase64Strict,
    locate: locate,
    sealInFile: sealInFile,
    verifyText: verifyText
  };
})(typeof globalThis !== 'undefined' ? globalThis : window);
