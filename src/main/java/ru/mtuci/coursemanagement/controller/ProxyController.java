package ru.mtuci.coursemanagement.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class ProxyController {
    @GetMapping("/api/proxy")
    public String proxy(@RequestParam("targetUrl") String targetUrl) {
        if (!targetUrl.startsWith("https://internal.mtuci.ru/")) {
            return "Доступ запрещен: разрешены только внутренние URL";
        }

        RestTemplate rt = new RestTemplate();
        return rt.getForObject(targetUrl, String.class);
    }
}
