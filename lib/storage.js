/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

"use strict";

import browser from "./browserAPI.js";
import {deriveKey, encryptData, decryptData, getDigest} from "./crypto.js";
import {EventTarget, emit} from "./eventTarget.js";

export const CURRENT_FORMAT = 3;
export const formatKey = "format";
export const saltKey = "salt";
export const hmacSecretKey = "hmac-secret";
export const prefsPrefix = "pref:";

let useridCallback = null;
export function setUseridCallback(callback)
{
  useridCallback = callback;
}

let keyCallback = null;
export function setKeyCallback(callback)
{
  keyCallback = callback;
}

let hmacSecretCallback = null;
export function setHmacSecretCallback(callback)
{
  hmacSecretCallback = callback;
}

function getKey()
{
  let key = keyCallback && keyCallback();
  if (!key)
    throw "master_password_required";

  return key;
}

export async function encrypt(data, key, json)
{
  if (typeof key == "undefined")
    key = getKey();

  if (!key)
    return data;

  if (json !== false)
    data = JSON.stringify(data);
  return await encryptData(key, data);
}

export async function decrypt(data, key, json)
{
  if (typeof key == "undefined")
    key = getKey();

  if (!key)
    return data;

  let plaintext = await decryptData(key, data);
  if (json !== false)
    plaintext = JSON.parse(plaintext);
  return plaintext;
}

export async function nameToStorageKey(data)
{
  let hmacSecret = hmacSecretCallback && hmacSecretCallback();
  if (!hmacSecret)
    throw "master_password_required";

  return await getDigest(hmacSecret, data);
}

function addPrefix(name)
{
  let userid = useridCallback && useridCallback();
  if (name.startsWith(prefsPrefix))
    throw "invalid_operation";
  if (!userid)
    throw "master_password_required";
  return `user:${userid}/${name}`;
}

function removePrefix(name)
{
  let prefix = addPrefix("");
  if (name.startsWith(prefix))
    return name.substring(prefix.length);
  throw "invalid_operation";
}

async function has(name)
{
  name = addPrefix(name);
  let items = await browser.storage.local.get(name);
  return items.hasOwnProperty(name);
}

async function hasPrefix(prefix)
{
  prefix = addPrefix(prefix);
  let items = await browser.storage.local.get(null);
  return Object.keys(items).some(name => name.startsWith(prefix));
}

async function get(name, key)
{
  name = addPrefix(name);
  let items = await browser.storage.local.get(name);
  if (!items.hasOwnProperty(name))
    return undefined;

  return await decrypt(items[name], key);
}

async function getAllByPrefix(prefix, key)
{
  let items = await browser.storage.local.get(null);
  let result = {};
  for (let name of Object.keys(items).filter(name => name.startsWith(addPrefix(prefix))))
    result[removePrefix(name)] = await decrypt(items[name], key);
  return result;
}

async function set(name, value, key)
{
  let ciphertext = await encrypt(value, key);
  await browser.storage.local.set({[addPrefix(name)]: ciphertext});
  await emit(storage, "set", name);
}

async function delete_(name)
{
  let names = Array.isArray(name) ? name : [name];
  await browser.storage.local.remove(names.map(addPrefix));
  await Promise.all(names.map(n => emit(storage, "delete", n)));
}

async function deleteByPrefix(prefix)
{
  let items = await browser.storage.local.get(null);
  let keys = Object.keys(items).filter(name => name.startsWith(addPrefix(prefix))).map(removePrefix);
  await delete_(keys);
}

async function clear()
{
  throw "invalid_operation";
}

let storage = Object.assign(EventTarget(), {
  has, hasPrefix, get, getAllByPrefix, set, delete: delete_, deleteByPrefix,
  clear
});
export default storage;
