import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { UploadService, UploadResult, AnalyseResult } from './upload.service';
import { VaultService } from '../auth/vault.service';
import { AuthService } from '../auth/auth.service';

type EncStatus = 'idle' | 'encrypting' | 'uploading' | 'detecting' | 'done' | 'error';

@Component({
  selector: 'app-upload',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './upload.html',
  styleUrl: './upload.css',
})
export class UploadComponent {
  private uploadService = inject(UploadService);
  private vault = inject(VaultService);
  private router = inject(Router);
  private auth = inject(AuthService);

  selectedFile: File | null = null;
  encStatus: EncStatus = 'idle';
  errorMessage = '';
  uploadResult: UploadResult | null = null;
  anomalyResult: AnalyseResult | null = null;
  isDragOver = false;

  get vaultLocked(): boolean {
    return !this.vault.isUnlocked;
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files?.length) this._setFile(input.files[0]);
  }

  onDragOver(event: DragEvent): void { event.preventDefault(); this.isDragOver = true; }
  onDragLeave(): void { this.isDragOver = false; }
  onDrop(event: DragEvent): void {
    event.preventDefault(); this.isDragOver = false;
    const file = event.dataTransfer?.files?.[0];
    if (file) this._setFile(file);
  }

  private _setFile(file: File): void {
    this.selectedFile = file;
    this.encStatus = 'idle';
    this.errorMessage = '';
    this.uploadResult = null;
    this.anomalyResult = null;
  }

  upload(): void {
    if (!this.selectedFile) return;
    this.encStatus = 'encrypting';
    this.errorMessage = '';

    setTimeout(() => {
      this.encStatus = 'uploading';
      this.uploadService.encryptAndUpload(this.selectedFile!).subscribe({
        next: (result: UploadResult) => {
          this.uploadResult = result;
          this.encStatus = 'detecting';
          this.uploadService.triggerDetection(result.metadata.metadata_id).subscribe({
            next: (anomaly: AnalyseResult) => { this.anomalyResult = anomaly; this.encStatus = 'done'; },
            error: () => { this.encStatus = 'done'; },
          });
        },
        error: (err: { error?: { error?: string } }) => {
          this.encStatus = 'error';
          this.errorMessage = err?.error?.error ?? 'Upload failed — please try again.';
        },
      });
    }, 300);
  }

  goToDashboard(): void { this.router.navigate(['/dashboard']); }
  logout(): void { this.auth.logout(); }

  get fileSizeLabel(): string {
    if (!this.selectedFile) return '';
    const b = this.selectedFile.size;
    if (b >= 1_048_576) return `${(b / 1_048_576).toFixed(1)} MB`;
    if (b >= 1_024) return `${(b / 1_024).toFixed(1)} KB`;
    return `${b} B`;
  }

  get statusLabel(): string {
    return ({
      idle: '', encrypting: 'Encrypting with your vault key (AES-256-GCM)…',
      uploading: 'Uploading encrypted payload…',
      detecting: 'Running anomaly detection (Z-score + IQR)…',
      done: 'Complete — plaintext never left your browser',
      error: 'Upload failed',
    } as Record<EncStatus, string>)[this.encStatus];
  }

  get statusClass(): string {
    return ({
      idle: '', encrypting: 'status-encrypting', uploading: 'status-uploading',
      detecting: 'status-detecting', done: 'status-done', error: 'status-error',
    } as Record<EncStatus, string>)[this.encStatus];
  }
}
