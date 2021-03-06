<!--
 - This Source Code is subject to the terms of the Mozilla Public License
 - version 2.0 (the "License"). You can obtain a copy of the License at
 - http://mozilla.org/MPL/2.0/.
 -->

<template>
  <div class="list">
    <shortcuts :letters="getLetters(sites)" @clicked="scrollToSite" />

    <site-info v-for="site in sites" :key="site.site"
               :ref="'site.' + site.site" :site="site" :show-notes="showNotes"
               :show-passwords="showPasswords" @removed="removeSite(site)"
    />
  </div>
</template>

<script>
"use strict";

import {getSiteDisplayName} from "../../common";
import {passwords} from "../../proxy";
import Shortcuts from "./Shortcuts.vue";
import SiteInfo from "./SiteInfo.vue";

export default {
  name: "SiteList",
  components: {
    "shortcuts": Shortcuts,
    "site-info": SiteInfo
  },
  props: {
    showNotes: {
      type: Boolean,
      required: true
    },
    showPasswords: {
      type: Boolean,
      required: true
    }
  },
  data()
  {
    return {
      sites: [],
    };
  },
  mounted()
  {
    this.updateData();
  },
  methods: {
    updateData()
    {
      passwords.getAllPasswords().then(sites =>
      {
        let siteNames = Object.keys(sites);
        siteNames.sort();
        {
          let index = siteNames.indexOf("pfp.invalid");
          if (index >= 0)
          {
            siteNames.splice(index, 1);
            siteNames.unshift("pfp.invalid");
          }
        }

        let siteList = [];
        for (let name of siteNames)
          siteList.push(sites[name]);
        this.sites = siteList;
      }).catch(this.$app.showUnknownError);
    },
    getLetters(sites)
    {
      let letters = [];
      let currentLetter = null;
      for (let site of sites)
      {
        let letter = getSiteDisplayName(site.site).toUpperCase()[0];
        if (letter != currentLetter && letter != "(")
        {
          currentLetter = letter;
          letters.push({letter, param: site.site});
        }
      }
      return letters;
    },
    scrollToSite(site)
    {
      this.$refs["site." + site][0].activate();
    },
    removeSite(site)
    {
      let index = this.sites.indexOf(site);
      if (index >= 0)
        this.sites.splice(index, 1);
    }
  }
};
</script>
