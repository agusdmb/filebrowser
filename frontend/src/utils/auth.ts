import { useAuthStore } from "@/stores/auth";
import router from "@/router";
import type { JwtPayload } from "jwt-decode";
import { jwtDecode } from "jwt-decode";
import { baseURL, noAuth } from "./constants";
import { StatusError } from "@/api/utils";

export function parseToken(token: string) {
  // falsy or malformed jwt will throw InvalidTokenError
  const data = jwtDecode<JwtPayload & { user: IUser }>(token);

  document.cookie = `auth=${token}; Path=/; SameSite=Strict;`;

  localStorage.setItem("jwt", token);

  const authStore = useAuthStore();
  authStore.jwt = token;
  authStore.setUser(data.user);
}

function getCookie(name: string): string | null {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return parts.pop()?.split(';').shift() || null;
  }
  return null;
}

export async function validateLogin() {
  try {
    let token = localStorage.getItem("jwt");
    
    // Check for token in URL query parameters (from OIDC callback)
    const urlParams = new URLSearchParams(window.location.search);
    const tokenFromUrl = urlParams.get('token');
    if (tokenFromUrl) {
      console.log("Found token in URL, parsing...");
      parseToken(tokenFromUrl);
      // Clean the URL by removing the token parameter
      const newUrl = new URL(window.location.href);
      newUrl.searchParams.delete('token');
      window.history.replaceState({}, '', newUrl.toString());
      return; // parseToken already sets up the auth state
    }
    
    // If no JWT in localStorage, check for auth cookie (e.g., from OIDC callback)
    if (!token) {
      const cookieToken = getCookie("auth");
      console.log("Checking for auth cookie:", cookieToken ? "found" : "not found");
      if (cookieToken) {
        console.log("Parsing token from cookie");
        // Parse and store the token from cookie
        parseToken(cookieToken);
        return; // parseToken already sets up the auth state
      }
    }
    
    if (token) {
      await renew(token);
    }
  } catch (error) {
    console.warn("Invalid JWT token in storage");
    throw error;
  }
}

export async function login(
  username: string,
  password: string,
  recaptcha: string
) {
  const data = { username, password, recaptcha };

  const res = await fetch(`${baseURL}/api/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  const body = await res.text();

  if (res.status === 200) {
    parseToken(body);
  } else {
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export async function renew(jwt: string) {
  const res = await fetch(`${baseURL}/api/renew`, {
    method: "POST",
    headers: {
      "X-Auth": jwt,
    },
  });

  const body = await res.text();

  if (res.status === 200) {
    parseToken(body);
  } else {
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export async function signup(username: string, password: string) {
  const data = { username, password };

  const res = await fetch(`${baseURL}/api/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  if (res.status !== 200) {
    throw new StatusError(`${res.status} ${res.statusText}`, res.status);
  }
}

export async function getOIDCConfig() {
  const res = await fetch(`${baseURL}/api/auth/oidc/config`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });

  if (res.status === 200) {
    return await res.json();
  } else {
    throw new StatusError(
      `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export function redirectToOIDC(authURL: string) {
  window.location.href = authURL;
}

export async function handleOIDCCallback() {
  // This function would be called when the user returns from OIDC provider
  // The callback endpoint should handle the token exchange and return a JWT
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const state = urlParams.get('state');

  if (!code) {
    throw new Error('No authorization code received from OIDC provider');
  }

  const res = await fetch(`${baseURL}/api/auth/oidc/callback?code=${code}&state=${state}`, {
    method: "GET",
  });

  const body = await res.text();

  if (res.status === 200) {
    parseToken(body);
    // Redirect to the intended page or home
    router.push({ path: "/" });
  } else {
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export function logout() {
  document.cookie = "auth=; Max-Age=0; Path=/; SameSite=Strict;";

  const authStore = useAuthStore();
  authStore.clearUser();

  localStorage.setItem("jwt", "");
  if (noAuth) {
    window.location.reload();
  } else {
    router.push({ path: "/login" });
  }
}
