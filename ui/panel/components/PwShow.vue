<!--
 - This Source Code is subject to the terms of the Mozilla Public License
 - version 2.0 (the "License"). You can obtain a copy of the License at
 - http://mozilla.org/MPL/2.0/.
 -->

<template>
  <ModalOverlay :focus-cancel="true" @cancel="$emit('cancel')">
    <div>
      <span>{{ password.site }} - </span>
      <span>{{ password.name }}</span>
      <span v-if="password.revision" class="password-revision">{{ password.revision }}</span>
    </div>
    <label class="block-start" for="pwshow-username">{{ $t(".(PasswordNameEntry)username_label") }}</label>
    <div class="pwshow-container">
      <input id="pwshow-username" spellcheck="false" autocomplete="off" :value="password.name" @focus="$event.target.select()">
    </div>
    <label class="block-start" for="pwshow-password">{{ $t(".(StoredPassword)password_label") }}</label>
    <div class="pwshow-container">
      <input id="pwshow-password" spellcheck="false" autocomplete="off" :value="value" @focus="$event.target.select()">
    </div>
    <label v-if="password.notes" class="block-start">{{ $t(".(NotesEditor)notes_label") }}</label>
    <div v-if="password.notes" class="pwshow-container notes">
      {{ password.notes }}
    </div>
  </ModalOverlay>
</template>

<script>
"use strict";

export default {
  name: "PwShow",
  localePath: "panel/components/PwShow",
  props: {
    password: {
      type: Object,
      required: true
    },
    value: {
      type: String,
      required: true
    }
  },
  emits: ["cancel"],
};
</script>
