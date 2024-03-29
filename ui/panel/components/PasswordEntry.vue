<!--
 - This Source Code is subject to the terms of the Mozilla Public License
 - version 2.0 (the "License"). You can obtain a copy of the License at
 - http://mozilla.org/MPL/2.0/.
 -->

<template>
  <div>
    <div class="password-container">
      <IconicLink
        class="password-menu-link iconic-link" tabindex="2"
        :class="{menuactive: modal == 'menu'}"
        :title="$t('password_menu')" @click="modal = 'menu'"
      />
      <IconicLink
        class="show-pwshow-link iconic-link" tabindex="3"
        :title="$t('show_pwshow')" @click="showPwShow"
      />
      <span class="user-name-container" tabindex="1" :title="tooltip" @click="fillIn" @keyup.enter="fillIn">
        <span>{{ password.name }}</span>
        <span v-if="password.revision" class="password-revision">{{ password.revision }}</span>
      </span>
    </div>

    <GeneratedPassword
      v-if="modal == 'generated'" :password="password"
      :options="passwordOptions" @cancel="modal = null"
    />
    <PasswordMenu
      v-if="modal == 'menu'" :password="password"
      @cancel="modal = null"
    />
    <PwShow
      v-if="modal == 'pwshow'" :password="password" :value="value"
      @cancel="modal = null"
    />
    <NotesEditor
      v-if="modal == 'notes'" :password="password"
      @cancel="modal = null"
    />
  </div>
</template>

<script>
"use strict";

import {set as clipboardSet} from "../../clipboard.js";
import {passwords, passwordRetrieval} from "../../proxy.js";
import GeneratedPassword from "./GeneratedPassword.vue";
import NotesEditor from "./NotesEditor.vue";
import PwShow from "./PwShow.vue";
import PasswordMenu from "./PasswordMenu.vue";

export default {
  name: "PasswordEntry",
  localePath: "panel/components/PasswordEntry",
  components: {
    GeneratedPassword,
    NotesEditor,
    PwShow,
    PasswordMenu
  },
  props: {
    password: {
      type: Object,
      required: true
    },
    focus: {
      type: Boolean,
      default: false
    }
  },
  data()
  {
    return {
      value: null,
      passwordOptions: null,
      modal: null
    };
  },
  computed: {
    tooltip()
    {
      let tooltip = "";
      let password = this.password;
      if (password.type.startsWith("generated"))
      {
        tooltip = this.$t("password_type_" + password.type);

        tooltip += "\n" + this.$t("password_length");
        tooltip += " " + password.length;

        tooltip += "\n" + this.$t("allowed_characters");
        if (password.lower)
          tooltip += " " + "abc";
        if (password.upper)
          tooltip += " " + "XYZ";
        if (password.number)
          tooltip += " " + "789";
        if (password.symbol)
          tooltip += " " + "+^;";
      }
      else if (password.type == "stored")
        tooltip = this.$t("password_type_stored");

      if (password.notes)
        tooltip += "\n" + this.$t("notes") + " " + password.notes;

      return tooltip;
    }
  },
  watch: {
    password()
    {
      this.value = null;
    }
  },
  methods: {
    ensureValue()
    {
      if (this.value)
        return Promise.resolve();

      return passwords.getPassword(this.password)
        .then(value =>
        {
          this.value = value;
        });
    },
    fillIn()
    {
      this.modal = null;
      passwordRetrieval.fillIn(this.password)
        .then(() => window.close())
        .catch(error => this.$parent.showPasswordMessage(error));
    },
    copy()
    {
      this.modal = null;

      let doCopy = () =>
      {
        clipboardSet(this.value);
        this.$parent.showPasswordMessage("password_copied");
      };

      if (this.value)
        doCopy();
      else
      {
        this.ensureValue().then(() =>
        {
          if (!this.$isWebClient)
            doCopy();
          else
          {
            this.$parent.showPasswordMessage("password_ready");
            let handler = event =>
            {
              window.removeEventListener("click", handler, true);
              event.stopPropagation();
              event.preventDefault();
              doCopy();
            };
            window.addEventListener("click", handler, true);
          }
        }).catch(error => this.$parent.showPasswordMessage(error));
      }
    },
    copyUsername()
    {
      this.modal = null;
      clipboardSet(this.password.name);
      this.$parent.showPasswordMessage("username_copied");
    },
    showPwShow()
    {
      this.modal = null;
      this.ensureValue().then(() =>
      {
        this.modal = "pwshow";
      }).catch(error => this.$parent.showPasswordMessage(error));
    },
    showNotes()
    {
      this.modal = "notes";
    },
    makeGenerated()
    {
      this.passwordOptions = {replacing: true};
      this.modal = "generated";
    },
    bumpRevision()
    {
      this.passwordOptions = {incRevision: true};
      this.modal = "generated";
    },
    removePassword()
    {
      this.modal = null;
      let message = this.$t("remove_confirmation", this.password.name, this.$root.siteDisplayName);
      if (this.password.notes)
        message += " " + this.$t("remove_confirmation_notes", this.password.notes);
      this.$root.confirm(message).then(response =>
      {
        if (response)
        {
          passwords.removePassword(this.password)
            .then(pwdList => this.$root.pwdList = pwdList)
            .catch(this.$parent.showPasswordMessage);
        }
      });
    }
  }
};
</script>
