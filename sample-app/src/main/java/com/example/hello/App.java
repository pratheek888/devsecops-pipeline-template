package com.example.hello;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/** Minimal HTTP service: GET /hello and GET /healthz. */
public final class App {

    static String greeting(String name) {
        String who = (name == null || name.isBlank()) ? "world" : name.replaceAll("[^A-Za-z0-9 _-]", "");
        return "{\"message\":\"hello, " + who + "\"}";
    }

    public static HttpServer start(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/hello", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            String name = query != null && query.startsWith("name=") ? query.substring(5) : null;
            respond(exchange, 200, greeting(name));
        });
        server.createContext("/healthz", exchange -> respond(exchange, 200, "{\"status\":\"ok\"}"));
        server.start();
        return server;
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int code, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        start(port);
        System.out.println("listening on :" + port);
    }
}
