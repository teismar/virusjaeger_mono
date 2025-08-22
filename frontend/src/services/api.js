import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
});

// Add token to requests automatically
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle token expiration
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  register: (userData) => api.post('/auth/register', userData),
  login: (credentials) => api.post('/auth/login', credentials, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  }),
  getCurrentUser: () => api.get('/auth/me'),
  createApiKey: (data) => api.post('/auth/api-keys', data),
  listApiKeys: () => api.get('/auth/api-keys'),
};

export const filesAPI = {
  uploadFile: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/files', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  },
  uploadFileMultiEngine: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/files/multi-engine', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  },
  getReport: (sha256) => api.get(`/files/${sha256}`),
  rescanFile: (sha256) => api.post('/files/rescan', { sha256 }),
};

export const searchAPI = {
  search: (query) => api.get(`/search?q=${encodeURIComponent(query)}`),
};

export const adminAPI = {
  listUsers: () => api.get('/admin/users'),
  updateUser: (userId, updates) => api.patch(`/admin/users/${userId}`, updates),
};

export const systemAPI = {
  health: () => api.get('/health'),
  statistics: () => api.get('/statistics'),
};

export default api;