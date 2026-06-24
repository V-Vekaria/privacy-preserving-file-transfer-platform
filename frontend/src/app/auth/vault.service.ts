import { Injectable } from '@angular/core';

const VAULT_KEY = 'st_vault_key';       // sessionStorage — cleared when tab closes
const PBKDF2_ITER = 200_000;

/**
 * VaultService — derives and holds the user's AES-256 master key in memory.
 *
 * Architecture (mirrors Bitwarden's model):
 *   password + server_key_salt  →  PBKDF2-SHA256 (200k iter)  →  AES-GCM master key
 *
 * The master key is used to encrypt/decrypt every file and every filename.
 * It is NEVER transmitted to the server. The server stores only the key_salt
 * (which is not secret — salts are always public in PBKDF2).
 *
 * The raw key bytes are stored in sessionStorage so the vault stays unlocked
 * across page navigations within the same tab, but is cleared when the tab closes.
 */
@Injectable({ providedIn: 'root' })
export class VaultService {
  private _key: CryptoKey | null = null;

  get isUnlocked(): boolean {
    return this._key !== null || !!sessionStorage.getItem(VAULT_KEY);
  }

  async deriveAndStore(password: string, keySaltB64: string): Promise<void> {
    const key = await this._derive(password, keySaltB64);
    this._key = key;
    // Persist raw bytes so vault survives navigation within the tab
    const raw = await crypto.subtle.exportKey('raw', key);
    sessionStorage.setItem(VAULT_KEY, this._toB64(raw));
  }

  async getKey(): Promise<CryptoKey> {
    if (this._key) return this._key;
    const stored = sessionStorage.getItem(VAULT_KEY);
    if (!stored) throw new Error('Vault is locked');
    const raw = this._fromB64(stored);
    this._key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return this._key;
  }

  lock(): void {
    this._key = null;
    sessionStorage.removeItem(VAULT_KEY);
  }

  /** Encrypt any string (e.g. a filename) with the vault key. Returns { enc, iv } base64 strings. */
  async encryptText(plaintext: string): Promise<{ enc: string; iv: string }> {
    const key = await this.getKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(plaintext);
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { enc: this._toB64(cipher), iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('') };
  }

  /** Decrypt a { enc, iv } pair back to plaintext. Returns null if decryption fails. */
  async decryptText(encB64: string, ivHex: string): Promise<string | null> {
    try {
      const key = await this.getKey();
      const iv = new Uint8Array(ivHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      const cipher = this._fromB64(encB64);
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
      return new TextDecoder().decode(plain);
    } catch {
      return null;
    }
  }

  /** Encrypt a file ArrayBuffer with the vault key + a fresh random IV + PBKDF2 salt. */
  async encryptFile(data: ArrayBuffer): Promise<{ ciphertextB64: string; ivHex: string; saltB64: string }> {
    const key = await this.getKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return {
      ciphertextB64: this._toB64(cipher),
      ivHex: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
      saltB64: '',   // vault key is used directly — no per-file passphrase needed
    };
  }

  /**
   * Wrap the vault key with a share passphrase so a recipient can decrypt
   * without ever knowing the owner's login password.
   *
   * Flow: PBKDF2(sharePassphrase, randomSalt) → wrapKey → AES-GCM encrypt(vaultKeyRaw)
   */
  async wrapVaultKey(sharePassphrase: string): Promise<{ wrappedKey: string; shareSalt: string; shareIv: string }> {
    // Read raw bytes directly from sessionStorage — the rehydrated CryptoKey is non-extractable
    const stored = sessionStorage.getItem(VAULT_KEY);
    if (!stored) throw new Error('Vault is locked');
    const vaultKeyRaw = this._fromB64(stored);

    const shareSaltBytes = crypto.getRandomValues(new Uint8Array(16));
    const shareIvBytes   = crypto.getRandomValues(new Uint8Array(12));

    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(sharePassphrase), 'PBKDF2', false, ['deriveKey']);
    const wrapKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: shareSaltBytes, iterations: 200_000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );

    const wrappedKeyBytes = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: shareIvBytes }, wrapKey, vaultKeyRaw);

    return {
      wrappedKey: this._toB64(wrappedKeyBytes),
      shareSalt:  this._toB64(shareSaltBytes.buffer),
      shareIv:    Array.from(shareIvBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
    };
  }

  /**
   * Unwrap a vault key using the recipient's share passphrase, then use it to decrypt the file
   * and (if provided) the original filename — so the recipient's download keeps its real name
   * and extension instead of falling back to a generic file_<id>.
   */
  async unwrapAndDecryptFile(
    wrappedKeyB64: string, shareSaltB64: string, shareIvHex: string,
    sharePassphrase: string,
    ciphertextB64: string, fileIvHex: string,
    filenameEncB64?: string | null, filenameIvHex?: string | null,
  ): Promise<{ data: ArrayBuffer; filename: string | null }> {
    const enc = new TextEncoder();
    const shareSalt = this._fromB64(shareSaltB64);
    const shareIv   = new Uint8Array(shareIvHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));

    const base = await crypto.subtle.importKey('raw', enc.encode(sharePassphrase), 'PBKDF2', false, ['deriveKey']);
    const wrapKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: shareSalt, iterations: 200_000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    const vaultKeyRaw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: shareIv }, wrapKey, this._fromB64(wrappedKeyB64));
    const vaultKey = await crypto.subtle.importKey('raw', vaultKeyRaw, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);

    const fileIv = new Uint8Array(fileIvHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
    const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fileIv }, vaultKey, this._fromB64(ciphertextB64));

    let filename: string | null = null;
    if (filenameEncB64 && filenameIvHex) {
      try {
        const nameIv = new Uint8Array(filenameIvHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
        const namePlain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nameIv }, vaultKey, this._fromB64(filenameEncB64));
        filename = new TextDecoder().decode(namePlain);
      } catch {
        filename = null;
      }
    }

    return { data, filename };
  }

  /** Decrypt a file using the vault key. */
  async decryptFile(ciphertextB64: string, ivHex: string): Promise<ArrayBuffer> {
    const key = await this.getKey();
    const iv = new Uint8Array(ivHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
    const cipher = this._fromB64(ciphertextB64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
  }

  private async _derive(password: string, keySaltB64: string): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const salt = this._fromB64(keySaltB64);
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      true,   // exportable so we can persist to sessionStorage
      ['encrypt', 'decrypt']
    );
  }

  private _toB64(buf: ArrayBuffer): string {
    const bytes = new Uint8Array(buf);
    let s = '';
    bytes.forEach(b => s += String.fromCharCode(b));
    return btoa(s);
  }

  private _fromB64(b64: string): ArrayBuffer {
    const s = atob(b64);
    const buf = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
    return buf.buffer;
  }
}
