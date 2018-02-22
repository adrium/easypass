/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

"use strict";

let storage = require("./storage");
let passwords = require("./passwords");
let masterPassword = require("./masterPassword");
let {lock, STORAGE_PREFIX: passwordsPrefix} = passwords;

const MILLIS_IN_SECOND = 1000;
const MILLIS_IN_MINUTE = 60 * MILLIS_IN_SECOND;
const MILLIS_IN_HOUR = 60 * MILLIS_IN_MINUTE;

function getProvider(provider)
{
  if (provider == "dropbox")
    return require("./sync-providers/dropbox");
  else
    throw new Error("Unknown sync provider");
}

let tracker = {
  enabled: false,
  prefix: "sync:",
  override: false,

  onModified(key)
  {
    if (this.override || !key.startsWith(passwordsPrefix))
      return Promise.resolve();

    return storage.set(this.prefix + key, true, null);
  },

  enable(startUp)
  {
    if (this.enabled)
      return Promise.resolve();

    this.enabled = true;
    let waitFor;
    if (startUp)
    {
      storage.addModificationListener(this.onModified);
      return Promise.resolve();
    }
    else
    {
      return storage.getAllByPrefix(passwordsPrefix, null).then(items =>
      {
        storage.addModificationListener(this.onModified);
        let actions = [];
        for (let key in items)
          actions.push(storage.set(this.prefix + key, true, null));
        return Promise.all(actions);
      });
    }
  },

  disable()
  {
    if (!this.enabled)
      return Promise.resolve();

    storage.removeModificationListener(this.onModified);
    this.enabled = false;
    return this.clearModifiedKeys();
  },

  getModifiedKeys()
  {
    return storage.getAllByPrefix(this.prefix, null).then(items =>
    {
      return new Set(Object.keys(items).map(key => key.substr(this.prefix.length)));
    });
  },

  clearModifiedKeys()
  {
    return storage.deleteByPrefix(this.prefix);
  }
};
tracker.onModified = tracker.onModified.bind(tracker);

let engine = {
  storageKey: "syncData",
  checkInterval: 10 * MILLIS_IN_MINUTE,
  syncInterval: MILLIS_IN_HOUR,
  data: null,
  currentSync: null,
  _timeout: null,

  init()
  {
    storage.get(this.storageKey, null).then(value =>
    {
      this.data = value;
      if (this.data)
      {
        tracker.enable(true);
        this._start();
      }
    });
  },

  _start()
  {
    this._stop();

    this._timeout = setInterval(this._check, this.checkInterval);
    this._check();
  },

  _stop()
  {
    if (this._timeout !== null)
      clearTimeout(this._timeout);
    this._timeout = null;
  },

  _check()
  {
    let now = Date.now();
    if (!this.data.lastSync || this.data.lastSync > now || now - this.data.lastSync >= this.syncInterval)
      this.sync();
  },

  sync()
  {
    if (this.currentSync)
      return this.currentSync;

    const path = "/passwords.json";
    let {provider, token} = this.data;

    this.currentSync = lock.acquire().then(() =>
    {
      return Promise.all([
        getProvider(provider).get(path, token),
        passwords.exportPasswordData(),
        tracker.getModifiedKeys()
      ]);
    }).then(([remoteData, localData, modifiedKeys]) =>
    {
      if (!remoteData)
      {
        return Promise.all([
          [],
          [],
          getProvider(provider).put(path, localData, null, token)
        ]);
      }

      let local = JSON.parse(localData);
      let remote;
      try
      {
        remote = JSON.parse(remoteData.contents);
      }
      catch (e)
      {
        throw "sync-unknown-data-format";
      }

      if (!remote || typeof remote != "object" ||
          remote.application != local.application ||
          remote.format != local.format ||
          !remote.data || typeof remote.data != "object" ||
          typeof remote.data[masterPassword.saltKey] != "string" ||
          typeof remote.data[masterPassword.hmacSecretKey] != "string")
      {
        throw "sync-unknown-data-format";
      }

      if (remote.data[masterPassword.saltKey] != local.data[masterPassword.saltKey])
        throw "todo-unimplemented";

      let modified = false;
      let additions = [];
      for (let key of Object.keys(remote.data))
      {
        if (!modifiedKeys.has(key))
        {
          local.data[key] = remote.data[key];
          additions.push([key, local.data[key]]);
        }
        else if (local.data[key] != remote.data[key])
          modified = true;
      }

      let removals = [];
      for (let key of Object.keys(local.data))
      {
        if (!remote.data.hasOwnProperty(key))
        {
          if (!modifiedKeys.has(key))
          {
            delete local.data[key];
            removals.push(key);
          }
          else
            modified = true;
        }
      }

      let updateAction;
      if (modified)
        updateAction = getProvider(provider).put(path, JSON.stringify(local), remoteData.revision, token);
      else
        updateAction = Promise.resolve();

      return Promise.all([
        additions,
        removals,
        updateAction
      ]);
    }).then(([additions, removals, _]) =>
    {
      if (this.data)
      {
        this.data.lastSync = Date.now();
        storage.set(this.storageKey, this.data, null);
      }

      tracker.override = true;
      let actions = [tracker.clearModifiedKeys()];
      for (let [key, value] of additions)
        actions.push(storage.set(key, value, null));
      for (let key of removals)
        actions.push(storage.delete(key));

      return Promise.all(actions);
    }).catch(e =>
    {
      if (e == "sync-wrong-revision")
      {
        // Remote revision changed, retry sync
        return this.sync();
      }
      else
        return this._reportError(e);
    }).finally(() =>
    {
      tracker.override = false;
      this.currentSync = null;
      triggerModificationListeners();
      lock.release();
    });

    delete this.data.error;
    triggerModificationListeners();
    return Promise.all([
      this.currentSync,
      storage.set(this.storageKey, this.data, null)
    ]);
  },

  _reportError(e)
  {
    if (!this.data)
      return Promise.resolve();

    this.data.error = String(e);
    if (typeof e != "string")
      console.error(e);
    triggerModificationListeners();
    return storage.set(this.storageKey, this.data, null);
  },

  setup(provider, token)
  {
    return lock.acquire().then(() =>
    {
      return tracker.enable();
    }).then(() =>
    {
      this.data = {provider, token};
      triggerModificationListeners();
      this._start();
      return storage.set(this.storageKey, this.data, null);
    }).finally(() => lock.release());
  },

  disable(noLock)
  {
    if (!this.data)
      return Promise.resolve();

    return (noLock ? Promise.resolve() : lock.acquire()).then(() =>
    {
      this.data = null;
      this._stop();
      triggerModificationListeners();
      return Promise.all([
        storage.delete(this.storageKey),
        tracker.disable()
      ]);
    }).finally(() => noLock || lock.release());
  }
};
engine._check = engine._check.bind(engine);
engine.init();

Object.defineProperty(exports, "syncData", {
  enumerable: true,
  get: () => engine.data
});

Object.defineProperty(exports, "isSyncing", {
  enumerable: true,
  get: () => !!engine.currentSync
});

exports.authorize = function(provider)
{
  return getProvider(provider).authorize().then(token =>
  {
    return engine.setup(provider, token);
  });
};

exports.disable = function(noLock)
{
  return engine.disable(noLock);
};

exports.sync = function()
{
  return engine.sync();
};

let modificationListeners = [];
function triggerModificationListeners()
{
  for (let listener of modificationListeners)
    listener();
}

function addModificationListener(listener)
{
  modificationListeners.push(listener);
}
exports.addModificationListener = addModificationListener;

function removeModificationListener(listener)
{
  let index = modificationListeners.indexOf(listener);
  if (index >= 0)
    modificationListeners.splice(index, 1);
}
exports.removeModificationListener = removeModificationListener;
