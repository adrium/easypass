/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

"use strict";

import browser from "./browserAPI.js";

const AES_KEY_SIZE = 256;

// I, l, O, 0, 1 excluded because of potential confusion. ", ', \ excluded
// because of common bugs in web interfaces (magic quotes).
const LOWERCASE = "abcdefghjkmnpqrstuvwxyz";
const UPPERCASE = "ABCDEFGHJKMNPQRSTUVWXYZ";
const NUMBER = "23456789";
const SYMBOL = "!#$%&()*+,-./:;<=>?@[]^_{|}~";

const ALLLOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const ALLUPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALLNUMBER = "0123456789";
const AEPSYMBOL = "!#$%&*+-?@";

let encoder = new TextEncoder("utf-8");
let decoder = new TextDecoder("utf-8");

let maxJobId = 0;
export let scryptWorker = null;

export function deriveBits(password, salt, length)
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
      resolve(result);
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

export async function derivePassword({masterPassword, type, domain, name, revision, length, lower, upper, number, symbol})
{
  let types = {
    generated2: {hasher: deriveBits, stringifier: toPassword},
    generatedAep: {hasher: deriveBits, stringifier: toPasswordAep},
  };

  let impl = types[type];
  if (!impl)
    throw "unknown_generation_method";

  let salt = domain + "\0" + name;
  if (revision)
    salt += "\0" + revision;

  let array = await impl.hasher(masterPassword, salt, length);
  return impl.stringifier(array, lower, upper, number, symbol);
}

export async function deriveKey({masterPassword, salt})
{
  let array = await deriveBits(masterPassword, atob(salt), AES_KEY_SIZE / 8);
  let key = await crypto.subtle.importKey(
    "raw", array, "AES-GCM", false, ["encrypt", "decrypt"]
  );
  return key;
}

export async function encryptData(key, plaintext)
{
  let initializationVector = new Uint8Array(12);
  crypto.getRandomValues(initializationVector);

  let buffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: initializationVector,
      tagLength: 128
    },
    key,
    encoder.encode(plaintext)
  );

  return toBase64(initializationVector) + "_" + toBase64(buffer);
}

export async function decryptData(key, ciphertext)
{
  let [initializationVector, data] = ciphertext.split("_", 2).map(fromBase64);

  let buffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: initializationVector,
      tagLength: 128
    },
    key,
    data
  );
  return decoder.decode(buffer);
}

export function generateRandom(length)
{
  let array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return toBase64(array);
}

export async function importHmacSecret(rawSecret)
{
  let key = await crypto.subtle.importKey(
    "raw",
    fromBase64(rawSecret),
    {name: "HMAC", hash: "SHA-256"},
    false,
    ["sign"]
  );
  return key;
}

export async function getDigest(hmacSecret, data)
{
  let signature = await crypto.subtle.sign(
    {name: "HMAC", hash: "SHA-256"},
    hmacSecret,
    encoder.encode(data)
  );
  return toBase64(signature);
}

function toPassword(array, lower, upper, number, symbol)
{
  let charsettings = [];

  if (lower)
    charsettings.push({charset: LOWERCASE, min: 1, max: 1024});
  if (upper)
    charsettings.push({charset: UPPERCASE, min: 1, max: 1024});
  if (number)
    charsettings.push({charset: NUMBER, min: 1, max: 1024});
  if (symbol)
    charsettings.push({charset: SYMBOL, min: 1, max: 1024});

  return toPasswordUniversal(array, charsettings);
}

function toPasswordAep(array, lower, upper, number, symbol)
{
  let charsettings = [];

  if (lower)
    charsettings.push({charset: ALLLOWERCASE, min: 2, max: 1024});
  if (upper)
    charsettings.push({charset: ALLUPPERCASE, min: 2, max: 1024});
  if (number)
    charsettings.push({charset: ALLNUMBER, min: 2, max: 1024});
  if (symbol)
    charsettings.push({charset: AEPSYMBOL, min: 2, max: 1024});

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
