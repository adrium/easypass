/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

"use strict";

import {toTypedArray} from "./typedArrayConversion";
import browser from "./browserAPI";

const AES_KEY_SIZE = 256;

let encoder = new TextEncoder("utf-8");
let decoder = new TextDecoder("utf-8");

let maxJobId = 0;
let scryptWorker = null;
let pbkdf2Worker = null;

function deriveBits(password, salt, length)
{
  return new Promise((resolve, reject) =>
  {
    if (!scryptWorker)
      scryptWorker = new Worker(browser.runtime.getURL("worker/scrypt.js"));

    let currentJobId = ++maxJobId;
    let messageCallback = ({data: {jobId, result}}) =>
    {
      if (jobId != currentJobId)
        return;
      cleanup();
      resolve(toTypedArray(result));
    };
    let errorCallback = () =>
    {
      cleanup();

      // The worker is probably in a bad state, create a new one next time.
      scryptWorker = null;

      reject("worker-error");
    };
    let cleanup = () =>
    {
      scryptWorker.removeEventListener("message", messageCallback);
      scryptWorker.removeEventListener("error", errorCallback);
    };

    scryptWorker.addEventListener("message", messageCallback);
    scryptWorker.addEventListener("error", errorCallback);
    scryptWorker.postMessage({
      jobId: currentJobId,
      password: encoder.encode(password),
      salt: encoder.encode(salt),
      length: parseInt(length, 10)
    });
  });
}

function deriveBitsLegacy(password, salt, length)
{
  return new Promise((resolve, reject) =>
  {
    if (!pbkdf2Worker)
      pbkdf2Worker = new Worker(browser.runtime.getURL("worker/pbkdf2.js"));

    let currentJobId = ++maxJobId;
    let messageCallback = ({data: {jobId, result}}) =>
    {
      if (jobId != currentJobId)
        return;
      cleanup();
      resolve(toTypedArray(result));
    };
    let errorCallback = () =>
    {
      cleanup();

      // The worker is probably in a bad state, create a new one next time.
      pbkdf2Worker = null;

      reject("worker-error");
    };
    let cleanup = () =>
    {
      pbkdf2Worker.removeEventListener("message", messageCallback);
      pbkdf2Worker.removeEventListener("error", errorCallback);
    };

    pbkdf2Worker.addEventListener("message", messageCallback);
    pbkdf2Worker.addEventListener("error", errorCallback);
    pbkdf2Worker.postMessage({
      jobId: currentJobId,
      password: encoder.encode(password),
      // Reserve 4 bytes at the end of the salt, PBKDF2 will need them
      salt: encoder.encode(salt + "    "),
      length: parseInt(length, 10)
    });
  });
}

export function derivePassword(params)
{
  params.type = "generated2";
  return derivePasswordUniversal(params);
}

export function deriveKey(params)
{
  return Promise.resolve().then(() =>
  {
    return deriveBits(params.masterPassword, atob(params.salt), AES_KEY_SIZE / 8);
  }).then(array =>
  {
    return crypto.subtle.importKey(
      "raw", array, "AES-GCM", false, ["encrypt", "decrypt"]
    );
  });
}

export function encryptData(key, plaintext)
{
  return Promise.resolve().then(() =>
  {
    let initializationVector = new Uint8Array(12);
    crypto.getRandomValues(initializationVector);

    return Promise.all([initializationVector, crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: initializationVector,
        tagLength: 128
      },
      key,
      encoder.encode(plaintext)
    )]);
  }).then(([initializationVector, buffer]) =>
  {
    let array = new Uint8Array(buffer);
    let result = [];
    for (let i = 0; i < array.length; i++)
      result.push(String.fromCharCode(array[i]));

    return toBase64(initializationVector) + "_" + toBase64(buffer);
  });
}

export function decryptData(key, ciphertext)
{
  return Promise.resolve().then(() =>
  {
    let [initializationVector, data] = ciphertext.split("_", 2).map(fromBase64);

    return crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: initializationVector,
        tagLength: 128
      },
      key,
      data
    );
  }).then(buffer =>
  {
    return decoder.decode(buffer);
  });
}

export function generateRandom(length)
{
  let array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return toBase64(array);
}

export function importHmacSecret(rawSecret)
{
  return Promise.resolve().then(() =>
  {
    return crypto.subtle.importKey(
      "raw",
      fromBase64(rawSecret),
      {name: "HMAC", hash: "SHA-256"},
      false,
      ["sign"]
    );
  });
}

export function getDigest(hmacSecret, data)
{
  return Promise.resolve().then(() =>
  {
    return crypto.subtle.sign(
      {name: "HMAC", hash: "SHA-256"},
      hmacSecret,
      encoder.encode(data)
    );
  }).then(signature =>
  {
    return toBase64(signature);
  });
}

export function derivePasswordLegacy(params)
{
  params.type = "generated";
  return derivePasswordUniversal(params);
}

export function derivePasswordUniversal(params)
{
  let types = {
    generated: {hasher: deriveBitsLegacy, stringifier: toPassword},
    generated2: {hasher: deriveBits, stringifier: toPassword}
  };

  let impl = types[params.type];

  if (impl == null)
    throw "unknown_generation_method";

  let salt = params.domain + "\0" + params.name;
  if (params.revision)
    salt += "\0" + params.revision;

  return Promise.resolve().then(() =>
  {
    return impl.hasher(params.masterPassword, salt, params.length);
  }).then(array =>
  {
    return impl.stringifier(array, params.lower, params.upper, params.number, params.symbol);
  });
}

function toPassword(array, lower, upper, number, symbol)
{
  let charsettings = [];

  if (lower)
    charsettings.push({charset: "abcdefghjkmnpqrstuvwxyz", min: 1, max: 1024});
  if (upper)
    charsettings.push({charset: "ABCDEFGHJKMNPQRSTUVWXYZ", min: 1, max: 1024});
  if (number)
    charsettings.push({charset: "23456789", min: 1, max: 1024});
  if (symbol)
    charsettings.push({charset: "!#$%&()*+,-./:;<=>?@[]^_{|}~", min: 1, max: 1024});

  return toPasswordUniversal(array, charsettings);
}

function toPasswordUniversal(array, charsettings)
{
  for (let s of charsettings)
    s.count = 0;

  let result = "";
  for (let i = 0; i < array.length; i++)
  {
    let sum = 0, max = 0, cnt = 0;

    for (let s of charsettings)
    {
      cnt = Math.max(0, s.min - s.count);
      max = Math.max(max, cnt);
      sum += cnt;
    }

    cnt = 0;
    for (let s of charsettings)
    {
      s.enabled = s.count < s.max && (sum < array.length - result.length || s.min - s.count == max);
      cnt += s.enabled ? s.charset.length : 0;
    }

    let index = cnt > 0 ? array[i] % cnt : 0;
    for (let s of charsettings)
    {
      if (s.enabled)
      {
        if (index < s.charset.length)
        {
          result += s.charset[index];
          s.count++;
          break;
        }
        index -= s.charset.length;
      }
    }
  }

  return result;
}

let pearsonHashPermutations = null;

export function pearsonHash(buffer, start, len, virtualByte)
{
  if (!pearsonHashPermutations)
  {
    pearsonHashPermutations = new Array(256);
    for (let i = 0; i < pearsonHashPermutations.length; i++)
      pearsonHashPermutations[i] = ((i + 379) * 467) & 0xFF;
  }

  let hash = pearsonHashPermutations[virtualByte];
  for (let i = start; i < start + len; i++)
    hash = pearsonHashPermutations[hash ^ buffer[i]];
  return hash;
}

export function toBase64(buffer)
{
  let array = new Uint8Array(buffer);
  let result = [];
  for (let i = 0; i < array.length; i++)
    result.push(String.fromCharCode(array[i]));

  return btoa(result.join(""));
}

export function fromBase64(string)
{
  let decoded = atob(string);
  let result = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++)
    result[i] = decoded.charCodeAt(i);

  return result;
}

// Our Base32 variant follows RFC 4648 but uses a custom alphabet to remove
// ambiguous characters: 0, 1, O, I.
export const base32Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function toBase32(buffer)
{
  let pos = 0;
  let current = 0;
  let currentBits = 0;
  let result = [];
  while (pos < buffer.length || currentBits >= 5)
  {
    if (currentBits < 5)
    {
      current = (current << 8) | buffer[pos++];
      currentBits += 8;
    }

    let remainder = currentBits - 5;
    result.push(base32Alphabet[current >> remainder]);
    current &= ~(31 << remainder);
    currentBits = remainder;
  }

  // Our input is always padded, so there should never be data left here
  if (currentBits)
    throw new Error("Unexpected: length of data encoded to base32 has to be a multiple of five");

  return result.join("");
}

export function fromBase32(str)
{
  str = str.replace(new RegExp(`[^${base32Alphabet}]`, "g"), "").toUpperCase();
  if (str.length % 8)
    throw new Error("Unexpected: length of data decoded from base32 has to be a multiple of eight");

  let mapping = new Map();
  for (let i = 0; i < base32Alphabet.length; i++)
    mapping.set(base32Alphabet[i], i);

  let pos = 0;
  let current = 0;
  let currentBits = 0;
  let result = new Uint8Array(str.length / 8 * 5);
  for (let i = 0; i < str.length; i++)
  {
    current = (current << 5) | mapping.get(str[i]);
    currentBits += 5;
    if (currentBits >= 8)
    {
      let remainder = currentBits - 8;
      result[pos++] = current >> remainder;
      current &= ~(31 << remainder);
      currentBits = remainder;
    }
  }
  return result;
}
