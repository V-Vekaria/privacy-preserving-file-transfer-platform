import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, from, switchMap } from 'rxjs';
import { environment } from '../../environments/environment';
import { VaultService } from '../auth/vault.service';

export interface FileRecord {
  file_id: number;
  filename: string;
  filename_enc: string | null;
  filename_iv: string | null;
  enc_file_size: number;
  uploaded_at: string;
  transfer_frequency: number;
  anomaly_flagged: boolean;
  anomaly_zscore: number | null;
  anomaly_iqr: string | null;
}

export interface UploadResult {
  message: string;
  file_id: number;
  metadata: {
    metadata_id: number;
    enc_file_size: number;
    timestamp: string;
    transfer_frequency: number;
  };
}

export interface AnalyseResult {
  metadata_id: number;
  is_flagged: boolean;
  zscore: number | null;
  iqr_flagged: boolean;
  sample_size: number;
}

@Injectable({ providedIn: 'root' })
export class UploadService {
  private http = inject(HttpClient);
  private vault = inject(VaultService);
  private apiUrl = `${environment.apiUrl}/files`;
  private detectionUrl = `${environment.apiUrl}/detection`;

  encryptAndUpload(file: File): Observable<UploadResult> {
    return from(this._encryptFile(file)).pipe(
      switchMap(payload =>
        this.http.post<UploadResult>(`${this.apiUrl}/upload`, payload)
      )
    );
  }

  triggerDetection(metadata_id: number): Observable<AnalyseResult> {
    return this.http.post<AnalyseResult>(`${this.detectionUrl}/analyse`, { metadata_id });
  }

  listFiles(): Observable<{ files: FileRecord[]; count: number }> {
    return this.http.get<{ files: FileRecord[]; count: number }>(this.apiUrl);
  }

  deleteFile(file_id: number): Observable<{ message: string }> {
    return this.http.delete<{ message: string }>(`${this.apiUrl}/${file_id}`);
  }

  dismissAnomaly(file_id: number): Observable<{ message: string }> {
    return this.http.patch<{ message: string }>(`${this.apiUrl}/${file_id}/dismiss-anomaly`, {});
  }

  downloadAndDecrypt(file_id: number): Observable<ArrayBuffer> {
    return this.http
      .get<{ ciphertext: string; iv: string }>(`${this.apiUrl}/${file_id}`)
      .pipe(
        switchMap(({ ciphertext, iv }) =>
          from(this.vault.decryptFile(ciphertext, iv))
        )
      );
  }

  createShareToken(
    file_id: number,
    wrapped: { wrappedKey: string; shareSalt: string; shareIv: string }
  ): Observable<{ token: string; expires_at: string; filename: string }> {
    return this.http.post<{ token: string; expires_at: string; filename: string }>(
      `${environment.apiUrl}/share/${file_id}`,
      { wrapped_key: wrapped.wrappedKey, share_salt: wrapped.shareSalt, share_iv: wrapped.shareIv }
    );
  }

  getSharedFile(token: string): Observable<{
    filename: string; ciphertext: string; iv: string; salt: string;
    expires_at: string; wrapped_key: string; share_salt: string; share_iv: string;
  }> {
    return this.http.get<any>(`${environment.apiUrl}/share/${token}`);
  }

  decryptShared(token: string, sharePassphrase: string): Observable<{ filename: string; data: ArrayBuffer }> {
    return this.getSharedFile(token).pipe(
      switchMap(res =>
        from(
          this.vault.unwrapAndDecryptFile(
            res.wrapped_key, res.share_salt, res.share_iv,
            sharePassphrase,
            res.ciphertext, res.iv,
          ).then(data => ({ filename: res.filename, data }))
        )
      )
    );
  }

  private async _encryptFile(file: File): Promise<Record<string, string>> {
    const plaintext = await file.arrayBuffer();
    const { ciphertextB64, ivHex, saltB64 } = await this.vault.encryptFile(plaintext);
    const { enc: filename_enc, iv: filename_iv } = await this.vault.encryptText(file.name);

    return {
      ciphertext: ciphertextB64,
      iv: ivHex,
      salt: saltB64,
      filename_enc,
      filename_iv,
    };
  }

  private _fromB64(b64: string): ArrayBuffer {
    const s = atob(b64);
    const buf = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
    return buf.buffer;
  }
}
