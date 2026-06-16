import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { UploadService, FileRecord } from '../upload/upload.service';
import { VaultService } from '../auth/vault.service';
import { AuthService } from '../auth/auth.service';

interface ResolvedFile extends FileRecord {
  displayName: string;   // decrypted filename, or plaintext fallback
}

interface ShareState {
  status: 'idle' | 'loading' | 'done' | 'error';
  link: string;
  expires: string;
  copied: boolean;
  passphrase: string;
  showPassphrase: boolean;
  passphraseError: string;
}

@Component({
  selector: 'app-files',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  templateUrl: './files.html',
  styleUrl: './files.css',
})
export class FilesComponent implements OnInit {
  private uploadService = inject(UploadService);
  private vault = inject(VaultService);
  private auth = inject(AuthService);

  files: ResolvedFile[] = [];
  loading = true;
  errorMessage = '';
  downloadStatus = new Map<number, 'idle' | 'downloading' | 'done' | 'error'>();
  downloadError = new Map<number, string>();
  shareStates = new Map<number, ShareState>();

  searchQuery = '';
  filterMode: 'all' | 'anomaly' | 'normal' = 'all';

  get vaultLocked(): boolean { return !this.vault.isUnlocked; }
  logout(): void { this.auth.logout(); }

  get filteredFiles(): ResolvedFile[] {
    return this.files.filter(f => {
      const matchesSearch = !this.searchQuery ||
        f.displayName.toLowerCase().includes(this.searchQuery.toLowerCase());
      const matchesFilter =
        this.filterMode === 'all' ||
        (this.filterMode === 'anomaly' && f.anomaly_flagged) ||
        (this.filterMode === 'normal' && !f.anomaly_flagged);
      return matchesSearch && matchesFilter;
    });
  }

  get anomalyCount(): number { return this.files.filter(f => f.anomaly_flagged).length; }

  ngOnInit(): void { this.loadFiles(); }

  loadFiles(): void {
    this.loading = true;
    this.uploadService.listFiles().subscribe({
      next: async res => {
        this.files = await Promise.all(res.files.map(f => this._resolve(f)));
        this.loading = false;
      },
      error: () => { this.errorMessage = 'Could not load files.'; this.loading = false; },
    });
  }

  private async _resolve(f: FileRecord): Promise<ResolvedFile> {
    let displayName = f.filename || `file_${f.file_id}`;
    if (f.filename_enc && f.filename_iv && this.vault.isUnlocked) {
      const decrypted = await this.vault.decryptText(f.filename_enc, f.filename_iv);
      if (decrypted) displayName = decrypted;
    }
    return { ...f, displayName };
  }

  download(file: ResolvedFile): void {
    this.downloadStatus.set(file.file_id, 'downloading');
    this.downloadError.delete(file.file_id);
    this.uploadService.downloadAndDecrypt(file.file_id).subscribe({
      next: (plaintext: ArrayBuffer) => {
        this._saveFile(plaintext, file.displayName);
        this.downloadStatus.set(file.file_id, 'done');
      },
      error: () => {
        this.downloadStatus.set(file.file_id, 'error');
        this.downloadError.set(file.file_id, 'Decryption failed — vault may be locked.');
      },
    });
  }

  getShare(id: number): ShareState {
    if (!this.shareStates.has(id))
      this.shareStates.set(id, {
        status: 'idle', link: '', expires: '', copied: false,
        passphrase: '', showPassphrase: false, passphraseError: '',
      });
    return this.shareStates.get(id)!;
  }

  share(file: ResolvedFile): void {
    const s = this.getShare(file.file_id);
    if (s.status === 'done') { this.copyLink(s); return; }
    if (!s.passphrase || s.passphrase.length < 6) {
      s.passphraseError = 'Enter a share passphrase (min 6 characters).';
      return;
    }
    s.passphraseError = '';
    s.status = 'loading';
    this.vault.wrapVaultKey(s.passphrase).then(wrapped => {
      this.uploadService.createShareToken(file.file_id, wrapped).subscribe({
        next: res => {
          s.link = `${window.location.origin}/shared/${res.token}`;
          s.expires = new Date(res.expires_at).toLocaleString();
          s.status = 'done';
          this.copyLink(s);
        },
        error: () => { s.status = 'error'; s.passphraseError = 'Failed to create share link.'; },
      });
    }).catch(() => { s.status = 'error'; s.passphraseError = 'Vault is locked — please log in again.'; });
  }

  copyLink(s: ShareState): void {
    navigator.clipboard.writeText(s.link).then(() => {
      s.copied = true;
      setTimeout(() => s.copied = false, 2500);
    });
  }

  dismissAnomaly(file: ResolvedFile): void {
    this.uploadService.dismissAnomaly(file.file_id).subscribe({
      next: () => {
        file.anomaly_flagged = false;
      },
      error: () => alert('Could not dismiss — please try again.'),
    });
  }

  avgSize(): string {
    if (!this.files.length) return '0 B';
    const avg = this.files.reduce((s, f) => s + f.enc_file_size, 0) / this.files.length;
    return this.formatSize(avg);
  }

  deleteFile(file: ResolvedFile): void {
    if (!confirm(`Delete "${file.displayName}"? This cannot be undone.`)) return;
    this.uploadService.deleteFile(file.file_id).subscribe({
      next: () => { this.files = this.files.filter(f => f.file_id !== file.file_id); },
      error: () => alert('Delete failed — please try again.'),
    });
  }

  formatSize(bytes: number): string {
    if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
    if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
    return `${bytes} B`;
  }

  formatDate(iso: string): string { return new Date(iso).toLocaleString(); }

  private _saveFile(data: ArrayBuffer, filename: string): void {
    const url = URL.createObjectURL(new Blob([data]));
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }
}
