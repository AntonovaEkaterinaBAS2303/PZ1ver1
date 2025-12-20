# Используем официальный образ OpenJDK 17
FROM eclipse-temurin:17-jre-alpine

# Устанавливаем рабочую директорию
WORKDIR /app

# Добавляем метаданные (без переменных GitHub Actions)
LABEL org.opencontainers.image.description="Application Docker Image"

# Копируем JAR файл в контейнер
COPY target/*.jar app.jar

# Создаем непривилегированного пользователя для безопасности
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Открываем порт, на котором работает приложение
EXPOSE 8080

# Команда для запуска приложения
ENTRYPOINT ["java", "-jar", "app.jar"]