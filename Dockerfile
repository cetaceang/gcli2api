# 步骤 1: 使用轻量的 slim 基础镜像
FROM python:3.13-slim

# 设置工作目录
WORKDIR /app

# 步骤 2: 复制依赖文件
COPY requirements.txt .

# 步骤 3: 使用 pip 安装 Python 依赖
# --no-cache-dir 是一个最佳实践，可以减小镜像体积
RUN pip install -r requirements.txt --no-cache-dir

# 步骤 4: 复制项目代码
COPY . .

# 步骤 5: 设置容器的默认启动命令
CMD ["python", "web.py"]
