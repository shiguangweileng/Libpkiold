// 后端API配置
const API_CONFIG = {
  // 后端服务器IP地址
  HOST: '127.0.0.1',
  // 后端服务器端口
  PORT: 8888,
  // 完整的API URL
  get BASE_URL() {
    return `http://${this.HOST}:${this.PORT}`;
  }
};

export default API_CONFIG; 