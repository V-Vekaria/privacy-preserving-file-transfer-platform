import { Routes } from '@angular/router';
import { LoginComponent } from './auth/login/login';
import { RegisterComponent } from './auth/register/register';
import { authGuard } from './auth/auth.guard';

export const routes: Routes = [
  {
    path: '',
    loadComponent: () => import('./home/home').then(m => m.HomeComponent),
    pathMatch: 'full',
  },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegisterComponent },
  {
    path: 'upload',
    canActivate: [authGuard],
    loadComponent: () =>
      import('./upload/upload').then(m => m.UploadComponent),
  },
  {
    path: 'files',
    canActivate: [authGuard],
    loadComponent: () =>
      import('./files/files').then(m => m.FilesComponent),
  },
  {
    path: 'dashboard',
    canActivate: [authGuard],
    loadComponent: () =>
      import('./dashboard/dashboard').then(m => m.Dashboard),
  },
  {
    path: 'shared/:token',
    loadComponent: () =>
      import('./shared/shared-download').then(m => m.SharedDownloadComponent),
  },
  { path: '**', redirectTo: 'login' },
];