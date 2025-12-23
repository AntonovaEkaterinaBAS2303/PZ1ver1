package ru.mtuci.coursemanagement.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Set;

@Slf4j
@Component
public class PluginLoader {
    @Value("${app.plugin.url:}")
    private String pluginUrl;

    private static final Set<String> ALLOWED_HOSTS = Set.of("localhost", "127.0.0.1");
    private static final Set<String> ALLOWED_PROTOCOLS = Set.of("file");

    public void tryLoad() {
        if (pluginUrl == null || pluginUrl.isBlank()) return;

        try {
            URL url = new URL(pluginUrl);

            if (!ALLOWED_PROTOCOLS.contains(url.getProtocol())) {
                log.error("Запрещенный протокол: {}", url.getProtocol());
                return;
            }

            if (!"file".equals(url.getProtocol()) && !ALLOWED_HOSTS.contains(url.getHost())) {
                log.error("Запрещенный хост: {}", url.getHost());
                return;
            }

            if (!verifyPluginIntegrity(url)) {
                log.error("Не удалось проверить целостность плагина");
                return;
            }

            URLClassLoader classLoader = new URLClassLoader(new URL[] { url });
            Class<?> pluginClass = classLoader.loadClass("ru.mtuci.coursemanagement.plugin.Plugin");
            Method mainMethod = pluginClass.getMethod("main", String[].class);
            mainMethod.invoke(null, (Object) new String[] {});

        } catch (Exception e) {
            log.error("Ошибка загрузки плагина: ", e);
        }
    }

    private boolean verifyPluginIntegrity(URL url) {
        return true;
    }
}