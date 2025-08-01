<template>
  <div id="login" :class="{ recaptcha: recaptcha }">
    <div v-if="oidcConfig.enabled" class="oidc-login">
      <img :src="logoURL" alt="File Browser" />
      <h1>{{ name }}</h1>
      <div v-if="error !== ''" class="wrong">{{ error }}</div>
      
      <button
        class="button button--block oidc-button"
        @click="loginWithOIDC"
        type="button"
      >
        {{ t('login.oidcLogin') }}
      </button>
    </div>
    
    <form v-else @submit="submit">
      <img :src="logoURL" alt="File Browser" />
      <h1>{{ name }}</h1>
      <div v-if="error !== ''" class="wrong">{{ error }}</div>

      <input
        autofocus
        class="input input--block"
        type="text"
        autocapitalize="off"
        v-model="username"
        :placeholder="t('login.username')"
      />
      <input
        class="input input--block"
        type="password"
        v-model="password"
        :placeholder="t('login.password')"
      />
      <input
        class="input input--block"
        v-if="createMode"
        type="password"
        v-model="passwordConfirm"
        :placeholder="t('login.passwordConfirm')"
      />

      <div v-if="recaptcha" id="recaptcha"></div>
      <input
        class="button button--block"
        type="submit"
        :value="createMode ? t('login.signup') : t('login.submit')"
      />

      <p @click="toggleMode" v-if="signup">
        {{ createMode ? t("login.loginInstead") : t("login.createAnAccount") }}
      </p>
    </form>
  </div>
</template>

<script setup lang="ts">
import { StatusError } from "@/api/utils";
import * as auth from "@/utils/auth";
import {
  name,
  logoURL,
  recaptcha,
  recaptchaKey,
  signup,
} from "@/utils/constants";
import { inject, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { useRoute, useRouter } from "vue-router";

// Define refs
const createMode = ref<boolean>(false);
const error = ref<string>("");
const username = ref<string>("");
const password = ref<string>("");
const passwordConfirm = ref<string>("");
const oidcConfig = ref<{ enabled: boolean; authURL?: string }>({ enabled: false });

const route = useRoute();
const router = useRouter();
const { t } = useI18n({});
// Define functions
const toggleMode = () => (createMode.value = !createMode.value);

const $showError = inject<IToastError>("$showError")!;

const loginWithOIDC = () => {
  if (oidcConfig.value.authURL) {
    auth.redirectToOIDC(oidcConfig.value.authURL);
  }
};

const submit = async (event: Event) => {
  event.preventDefault();
  event.stopPropagation();

  const redirect = (route.query.redirect || "/files/") as string;

  let captcha = "";
  if (recaptcha) {
    captcha = window.grecaptcha.getResponse();

    if (captcha === "") {
      error.value = t("login.wrongCredentials");
      return;
    }
  }

  if (createMode.value) {
    if (password.value !== passwordConfirm.value) {
      error.value = t("login.passwordsDontMatch");
      return;
    }
  }

  try {
    if (createMode.value) {
      await auth.signup(username.value, password.value);
    }

    await auth.login(username.value, password.value, captcha);
    router.push({ path: redirect });
  } catch (e: any) {
    // console.error(e);
    if (e instanceof StatusError) {
      if (e.status === 409) {
        error.value = t("login.usernameTaken");
      } else if (e.status === 403) {
        error.value = t("login.wrongCredentials");
      } else {
        $showError(e);
      }
    }
  }
};

// Run hooks
onMounted(async () => {
  // Check if this is an OIDC callback
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('code')) {
    try {
      await auth.handleOIDCCallback();
      return; // Exit early if OIDC callback is handled
    } catch (e) {
      console.error('OIDC callback error:', e);
      error.value = t('login.oidcError');
    }
  }

  // Check OIDC configuration
  try {
    oidcConfig.value = await auth.getOIDCConfig();
  } catch (e) {
    console.warn('Failed to get OIDC config:', e);
    // Fall back to regular login
  }

  // Initialize reCAPTCHA if needed and not using OIDC
  if (!recaptcha || oidcConfig.value.enabled) return;

  window.grecaptcha.ready(function () {
    window.grecaptcha.render("recaptcha", {
      sitekey: recaptchaKey,
    });
  });
});
</script>
