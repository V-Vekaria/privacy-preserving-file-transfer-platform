import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [FormsModule, RouterLink, CommonModule],
  templateUrl: './register.html',
  styleUrls: ['./register.css']
})
export class RegisterComponent {
  username = '';
  email = '';
  password = '';
  confirmPassword = '';
  showPassword = false;
  errorMessage = '';
  loading = false;

  private auth = inject(AuthService);
  private router = inject(Router);

  onSubmit(): void {
    if (!this.username || !this.email || !this.password) {
      this.errorMessage = 'Username, email, and password are required.';
      return;
    }
    if (!this.email.includes('@')) {
      this.errorMessage = 'A valid email address is required.';
      return;
    }
    if (this.password !== this.confirmPassword) {
      this.errorMessage = 'Passwords do not match.';
      return;
    }
    if (this.password.length < 8) {
      this.errorMessage = 'Password must be at least 8 characters.';
      return;
    }
    this.loading = true;
    this.errorMessage = '';
    this.auth.register(this.username, this.email, this.password).subscribe({
      next: () => this.router.navigate(['/dashboard']),
      error: err => {
        this.errorMessage = err.error?.error || 'Registration failed. Please try again.';
        this.loading = false;
      }
    });
  }
}