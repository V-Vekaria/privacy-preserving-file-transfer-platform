import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { UploadService, UploadResult } from './upload.service';

type EncStatus = 'idle' | 'encrypting' | 'uploading' | 'done' | 'error';

@Component({
  selector: 'app-upload',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './upload.html',
  styleUrl: './upload.css',
})
export class UploadComponent {
  private uploadService = inject(UploadService);
  private router = inject(Router);

  selectedFile: File | null = null;
  encStatus: EncStatus = 'idle';
  errorMessage = '';
  uploadResult: UploadResult | null = null;
  isDragOver = false;

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files?.length) {
      this._setFile(input.files[0]);
    }
  }

  onDragOver(event: DragEvent): void {
    event.preventDefault();
    this.isDragOver = true;
  }

  onDragLeave(): void {
    this.isDragOver = false;
  }

  onDrop(event: DragEvent): void {
    event.preventDefault();
    this.isDragOver = false;
    const file = event.dataTransfer?.files?.[0];
    if (file) this._setFile(file);
  }

  private _setFile(file: File): void {
    this.selectedFile = file;
    this.encStatus = 'idle';
    this.errorMessage = '';
    this.uploadResult = null;
  }

  upload(): void {
    if (!this.selectedFile) return;

    this.encStatus = 'encrypting';
    this.errorMessage = '';

    setTimeout(() => {
      this.encStatus = 'uploading';
      this.uploadService.encryptAndUpload(this.selectedFile!).subscribe({
        next: (result: UploadResult) => {
          this.encStatus = 'done';
          this.uploadResult = result;
        },
        error: (err: { error?: { error?: string } }) => {
          this.encStatus = 'error';
          this.errorMessage =
            err?.error?.error ?? 'Upload failed — please try again.';
        },
      });
    }, 300);
  }

  goToDashboard(): void {
    this.router.navigate(['/dashboard']);
  }

  get fileSizeLabel(): string {
    if (!this.selectedFile) return '';
    const bytes = this.selectedFile.size;
    if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
    if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
    return `${bytes} B`;
  }

  get statusLabel(): string {
    const map: Record<EncStatus, string> = {
      idle: '',
      encrypting: 'Encrypting client-side… AES-GCM',
      uploading: 'Uploading encrypted payload…',
      done: 'Upload complete — key retained client-side only',
      error: 'Upload failed',
    };
    return map[this.encStatus];
  }

  get statusClass(): string {
    const map: Record<EncStatus, string> = {
      idle: '',
      encrypting: 'status-encrypting',
      uploading: 'status-uploading',
      done: 'status-done',
      error: 'status-error',
    };
    return map[this.encStatus];
  }
}