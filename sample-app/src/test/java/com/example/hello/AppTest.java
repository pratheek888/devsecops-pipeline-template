package com.example.hello;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;

class AppTest {

    @Test
    void greetingSanitisesInput() {
        assertEquals("{\"message\":\"hello, world\"}", App.greeting(null));
        assertEquals("{\"message\":\"hello, bobscript\"}", App.greeting("bob</script>"));
    }

    @Test
    void serves() throws Exception {
        HttpServer server = App.start(0);
        try {
            int port = server.getAddress().getPort();
            HttpResponse<String> r = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/healthz")).build(),
                HttpResponse.BodyHandlers.ofString());
            assertEquals(200, r.statusCode());
        } finally {
            server.stop(0);
        }
    }
}
