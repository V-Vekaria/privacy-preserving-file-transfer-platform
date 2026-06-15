import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface StatCards {
  total_uploads: number;
  flagged_anomalies: number;
  avg_file_size_bytes: number;
}

export interface FrequencyPoint {
  date: string;
  count: number;
}

export interface SizeBucket {
  label: string;
  count: number;
}

export interface AnomalyEvent {
  event_id: number;
  enc_file_size: number;
  timestamp: string;
  z_score: number | null;
  iqr_label: string;
  anomaly_flag: boolean;
}

export interface DashboardStats {
  stat_cards: StatCards;
  frequency_chart: FrequencyPoint[];
  size_distribution: SizeBucket[];
  anomaly_events: AnomalyEvent[];
}

@Injectable({ providedIn: 'root' })
export class DashboardService {
  private http = inject(HttpClient);
  private apiUrl = `${environment.apiUrl}/dashboard`;

  getStats(): Observable<DashboardStats> {
    return this.http.get<DashboardStats>(`${this.apiUrl}/stats`);
  }
}