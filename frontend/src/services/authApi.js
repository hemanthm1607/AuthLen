/**
 * services/authApi.js — Frontend Authentication & Testing Engine API Client
 * Connects React UI to the Express backend with credentials (session cookies).
 */
// On Vercel (production), API is routed on the same domain (/api/...) unless an explicit VITE_API_URL is provided.
// In local development, falls back to http://localhost:4000.
const API_BASE = import.meta.env.VITE_API_URL !== undefined
  ? import.meta.env.VITE_API_URL
  : (import.meta.env.PROD ? '' : 'http://localhost:4000');

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const defaultHeaders = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  };

  const config = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
    credentials: 'include', // Automatically send and receive session cookies
  };

  try {
    const res = await fetch(url, config);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const error = new Error(data.error || `Request failed with status ${res.status}`);
      error.status = res.status;
      error.data = data;
      throw error;
    }

    return data;
  } catch (err) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      const connErr = new Error('Could not connect to backend server. Please verify backend service status.');
      connErr.isConnectionError = true;
      throw connErr;
    }
    throw err;
  }
}

export const authApi = {
  // Session verification on app launch
  async getMe() {
    return request('/api/auth/me');
  },

  // Sign In
  async login({ email, password }) {
    return request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  // Register
  async register({ fullName, email, password }) {
    return request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ fullName, email, password }),
    });
  },

  // Logout
  async logout() {
    return request('/api/auth/logout', {
      method: 'POST',
    });
  },

  // Password Recovery
  async forgotPassword({ email }) {
    return request('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  // Password Reset
  async resetPassword({ token, newPassword }) {
    return request('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, newPassword }),
    });
  },

  // Email Verification
  async verifyEmail({ token }) {
    return request('/api/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  },

  // Health check
  async checkHealth() {
    return request('/api/health');
  },

  // ── Testing Engine & Assessment Endpoints ──
  async runAssessment({ targetUrl = 'http://localhost:4000', isAuthorized = true } = {}) {
    return request('/api/assessments/run', {
      method: 'POST',
      body: JSON.stringify({ targetUrl, isAuthorized }),
    });
  },

  async getAssessmentHistory() {
    return request('/api/assessments/history');
  },

  async getAssessmentById(id) {
    return request(`/api/assessments/${id}`);
  },

  async getUserSettings() {
    return request('/api/settings');
  },

  async updateUserSettings(settings) {
    return request('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  },

  // ── AI Recommendations Endpoints ──
  async getAiStatus() {
    return request('/api/ai/status');
  },

  async generateAiRecommendations(assessmentId, options = {}) {
    return request('/api/ai/generate', {
      method: 'POST',
      body: JSON.stringify({ assessmentId, ...options }),
    });
  },

  // ── AI Code Remediation Workflow Endpoints ──
  async getProjectRemediationStatus() {
    return request('/api/remediations/project/status');
  },

  async getRemediations(assessmentId, status) {
    const params = new URLSearchParams();
    if (assessmentId) params.append('assessmentId', assessmentId);
    if (status) params.append('status', status);
    const queryString = params.toString() ? `?${params.toString()}` : '';
    return request(`/api/remediations${queryString}`);
  },

  async getRemediationById(id) {
    return request(`/api/remediations/${id}`);
  },

  async generateRemediations(assessmentId, options = {}) {
    const payload = { assessmentId };
    if (options.forceAdapter) payload.forceAdapter = options.forceAdapter;
    if (options.model) payload.model = options.model;
    if (options.projectRoot) payload.projectRoot = options.projectRoot;
    if (Array.isArray(options.recommendations)) payload.recommendations = options.recommendations;
    if (options.provider) payload.provider = options.provider;

    return request('/api/remediations/generate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async approveRemediation(id) {
    return request(`/api/remediations/${id}/approve`, {
      method: 'POST',
    });
  },

  async rejectRemediation(id, reason) {
    return request(`/api/remediations/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },

  async applyRemediation(id) {
    return request(`/api/remediations/${id}/apply`, {
      method: 'POST',
    });
  },

  async verifyRemediation(id, command) {
    return request(`/api/remediations/${id}/verify`, {
      method: 'POST',
      body: JSON.stringify({ command }),
    });
  },

  async rollbackRemediation(id) {
    return request(`/api/remediations/${id}/rollback`, {
      method: 'POST',
    });
  },
};

