import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, from, switchMap } from 'rxjs';
import { environment } from '../../environments/environment';

export interface UploadResult {
  message: string;
  file_id: number;
  metadata: {
    enc_file_size: number;
    timestamp: string;
    transfer_frequency: number;
  };
}

@Injectable({ providedIn: 'root' })
export class UploadService {
  private http = inject(HttpClient);
  private apiUrl = `${environment.apiUrl}/files`;

  encryptAndUpload(file: File): Observable<UploadResult> {
    return from(this._encryptFile(file)).pipe(
      switchMap(({ ciphertextB64, ivHex }: { ciphertextB64: string; ivHex: string }) =>
        this.http.post<UploadResult>(`${this.apiUrl}/upload`, {
          ciphertext: ciphertextB64,
          iv: ivHex,
        })
      )
    );
  }

  private async _encryptFile(
    file: File
  ): Promise<{ ciphertextB64: string; ivHex: string }> {
    const plaintext = await file.arrayBuffer();

    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      plaintext
    );

    return {
      ciphertextB64: this._arrayBufferToBase64(ciphertext),
      ivHex: Array.from(iv)
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join(''),
    };
  }

  private _arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    bytes.forEach((b: number) => (binary += String.fromCharCode(b)));
    return btoa(binary);
  }
}