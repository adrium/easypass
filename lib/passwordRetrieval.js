/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

"use strict";

import browser from "./browserAPI";
import {getCurrentHost} from "./ui";
import {getPassword, getAlias} from "./passwords";
import {getPort} from "./messaging";

let maxScriptID = 0;

export function fillIn(passwordData)
{
  return Promise.all([
    getPassword(passwordData),
    getCurrentHost().then(currentHost => Promise.all([currentHost, getAlias(currentHost)]))
  ]).then(([password, [currentHost, [_, currentSite]]]) =>
  {
    if (currentSite != passwordData.site)
      return Promise.reject("wrong_site");

    return new Promise((resolve, reject) =>
    {
      let scriptID = ++maxScriptID;
      let port = getPort("contentScript");

      port.on("done", function doneHandler({scriptID: source, result})
      {
        if (source != scriptID)
          return;

        port.off("done", doneHandler);
        if (result)
          reject(result);
        else
        {
          resolve();

          // Make sure that the popup is closed on Firefox Android,
          // work-around for https://bugzil.la/1433604
          browser.tabs.update({active: true});
        }
      });

      browser.tabs.executeScript({
        code: "var _parameters = " + JSON.stringify({
          scriptID,
          host: currentHost,
          name: passwordData.name,
          password
        })
      }).catch(reject);

      browser.tabs.executeScript({file: "contentScript/fillIn.js"}).catch(reject);
    });
  });
}
