import {
  Component,
  OnInit,
  AfterViewInit,
  OnDestroy,
  inject,
  signal,
  computed,
  ElementRef,
  viewChild,
} from '@angular/core';
import { CommonModule, DecimalPipe, DatePipe, TitleCasePipe } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { Chart, registerables } from 'chart.js';
import {
  DashboardService,
  DashboardStats,
  AnomalyEvent,
  FrequencyPoint,
  SizeBucket,
} from './dashboard.service';
import { AuthService } from '../auth/auth.service';

Chart.register(...registerables);

type EventFilter = 'all' | 'flagged';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, DecimalPipe, DatePipe, TitleCasePipe, RouterLink],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.css',
})
export class Dashboard implements OnInit, AfterViewInit, OnDestroy {
  private dashService = inject(DashboardService);
  private router = inject(Router);
  private auth = inject(AuthService);

  freqCanvas = viewChild<ElementRef<HTMLCanvasElement>>('freqCanvas');
  sizeCanvas = viewChild<ElementRef<HTMLCanvasElement>>('sizeCanvas');

  stats = signal<DashboardStats | null>(null);
  loading = signal(true);
  error = signal('');
  filter = signal<EventFilter>('all');

  private freqChart: Chart | null = null;
  private sizeChart: Chart | null = null;

  filteredEvents = computed<AnomalyEvent[]>(() => {
    const s = this.stats();
    if (!s) return [];
    return this.filter() === 'flagged'
      ? s.anomaly_events.filter((e: AnomalyEvent) => e.anomaly_flag)
      : s.anomaly_events;
  });

  ngOnInit(): void {
    this.dashService.getStats().subscribe({
      next: (data: DashboardStats) => {
        this.stats.set(data);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Failed to load dashboard data.');
        this.loading.set(false);
      },
    });
  }

  ngAfterViewInit(): void {
    const interval = setInterval(() => {
      if (this.stats()) {
        this._buildCharts();
        clearInterval(interval);
      }
    }, 100);
  }

  ngOnDestroy(): void {
    this.freqChart?.destroy();
    this.sizeChart?.destroy();
  }

  private _buildCharts(): void {
    const data = this.stats()!;

    const freqEl = this.freqCanvas()?.nativeElement;
    const sizeEl = this.sizeCanvas()?.nativeElement;

    if (freqEl) {
      this.freqChart = new Chart(freqEl, {
        type: 'line',
        data: {
          labels: data.frequency_chart.map((p: FrequencyPoint) => p.date),
          datasets: [
            {
              label: 'Uploads per day',
              data: data.frequency_chart.map((p: FrequencyPoint) => p.count),
              borderColor: '#1a5fa8',
              backgroundColor: 'rgba(26,95,168,0.1)',
              fill: true,
              tension: 0.3,
              pointRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
        },
      });
    }

    if (sizeEl) {
      this.sizeChart = new Chart(sizeEl, {
        type: 'bar',
        data: {
          labels: data.size_distribution.map((b: SizeBucket) => b.label),
          datasets: [
            {
              label: 'File count',
              data: data.size_distribution.map((b: SizeBucket) => b.count),
              backgroundColor: 'rgba(26,95,168,0.7)',
              borderRadius: 4,
            },
          ],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
        },
      });
    }
  }

  setFilter(f: EventFilter): void {
    this.filter.set(f);
  }

  formatBytes(bytes: number): string {
    if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
    if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
    return `${bytes} B`;
  }

  goToUpload(): void {
    this.router.navigate(['/upload']);
  }

  logout(): void {
    this.auth.logout();
  }

  get username(): string | null {
    return this.auth.getUsername();
  }
}