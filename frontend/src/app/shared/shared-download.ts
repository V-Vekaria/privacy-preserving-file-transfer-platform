import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute } from '@angular/router';
import { UploadService } from '../upload/upload.service';

type Status = 'idle' | 'loading' | 'decrypting' | 'done' | 'error' | 'expired' | 'invalid';

@Component({
  selector: 'app-shared-download',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './shared-download.html',
  styleUrl: './shared-download.css',
})
export class SharedDownloadComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private uploadService = inject(UploadService);

  token = '';
  filename = '';
  expiresAt = '';
  passphrase = '';
  showPassphrase = false;
  status: Status = 'loading';
  errorMsg = '';

  ngOnInit(): void {
    this.token = this.route.snapshot.paramMap.get('token') ?? '';
    this.uploadService.getSharedFile(this.token).subscribe({
      next: res => {
        this.filename = res.filename;
        this.expiresAt = new Date(res.expires_at).toLocaleString();
        this.status = 'idle';
      },
      error: err => {
        this.status = err.status === 410 ? 'expired' : 'error';
        this.errorMsg = err.error?.error ?? 'Invalid or expired share link.';
      },
    });
  }

  decrypt(): void {
    if (!this.passphrase || this.passphrase.length < 6) {
      this.errorMsg = 'Passphrase must be at least 6 characters.';
      return;
    }
    this.status = 'decrypting';
    this.errorMsg = '';
    this.uploadService.decryptShared(this.token, this.passphrase).subscribe({
      next: ({ filename, data }) => {
        const blob = new Blob([data]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename; a.click();
        URL.revokeObjectURL(url);
        this.status = 'done';
      },
      error: () => {
        this.status = 'error';
        this.errorMsg = 'Decryption failed — wrong passphrase or link has been revoked.';
      },
    });
  }
}
