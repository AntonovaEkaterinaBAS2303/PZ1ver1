package ru.mtuci.coursemanagement.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

@Slf4j
@Component
public class PluginLoader {
    @Value("${app.plugin.url:}")
    private String pluginUrl;

    public void tryLoad() {
        if (pluginUrl == null || pluginUrl.isBlank()) return;

        if (pluginUrl.startsWith("http://") || pluginUrl.startsWith("https://")) {
            log.warn("Загрузка плагинов из внешних источников запрещена");
            return;
        }

        if (!pluginUrl.startsWith("file:/")) {
            log.error("Разрешена только загрузка из локальных файлов");
            return;
        }
    }
}