// frontend/lib/api/client.ts
import axios from 'axios';
import Cookies from 'js-cookie';

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080',
  withCredentials: true, // Обязательно для отправки и получения cookies
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
  },
});

// Интерсептор запросов: автоматически получаем CSRF-токен перед мутирующими запросами
apiClient.interceptors.request.use(async (config) => {
  const method = config.method?.toLowerCase();
  
  if (method && ['post', 'put', 'delete', 'patch'].includes(method)) {
    try {
      await axios.get(`${apiClient.defaults.baseURL}/sanctum/csrf-cookie`, {
        withCredentials: true,
      });
      
      const token = Cookies.get('XSRF-TOKEN');
      if (token) {
        config.headers['X-XSRF-TOKEN'] = decodeURIComponent(token);
      }
      // config.headers['Origin'] = process.env.NEXT_PUBLIC_FRONTEND_URL || 'http://localhost:3001';
      
      console.log('CSRF-токен добавлен:', token ? 'OK' : 'ОТСУТСТВУЕТ');
    } catch (error) {
      console.error('Ошибка получения CSRF-токена:', error);
    }
  }
  
  return config;
});

// Интерсептор ответов: обработка ошибок
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.error(' Ошибка 401: Пользователь не авторизован');
    }
    return Promise.reject(error);
  }
);

export default apiClient;