import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, from, switchMap } from 'rxjs';
import { environment } from '../../environments/environment';
import { VaultService } from './vault.service';

export interface AuthResponse {
  token: string;
  key_salt: string;
  message?: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly TOKEN_KEY = 'st_token';
  private http = inject(HttpClient);
  private router = inject(Router);
  private vault = inject(VaultService);

  register(username: string, email: string, password: string): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>(`${environment.apiUrl}/auth/register`, { username, email, password })
      .pipe(
        tap(res => this.storeToken(res.token)),
        switchMap(res =>
          from(this.vault.deriveAndStore(password, res.key_salt).then(() => res))
        )
      );
  }

  login(username: string, password: string): Observable<AuthResponse> {
    return this.http
      .post<AuthResponse>(`${environment.apiUrl}/auth/login`, { username, password })
      .pipe(
        tap(res => this.storeToken(res.token)),
        switchMap(res =>
          from(this.vault.deriveAndStore(password, res.key_salt).then(() => res))
        )
      );
  }

  logout(): void {
    this.vault.lock();
    localStorage.removeItem(this.TOKEN_KEY);
    this.router.navigate(['/']);
  }

  getToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  getUsername(): string | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      return JSON.parse(atob(token.split('.')[1])).username ?? null;
    } catch {
      return null;
    }
  }

  isLoggedIn(): boolean {
    const token = this.getToken();
    if (!token) return false;
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp * 1000 > Date.now();
    } catch {
      return false;
    }
  }

  private storeToken(token: string): void {
    localStorage.setItem(this.TOKEN_KEY, token);
  }
}
