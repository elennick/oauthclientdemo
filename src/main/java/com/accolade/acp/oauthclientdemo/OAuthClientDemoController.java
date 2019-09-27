package com.accolade.acp.oauthclientdemo;

import com.nimbusds.jose.util.Base64URL;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;

import static org.springframework.web.reactive.function.client.ExchangeFilterFunctions.basicAuthentication;

@Slf4j
@Controller
public class OAuthClientDemoController {

    private final String clientId;
    private final String clientSecret;
    private final String tokenEndpoint;
    private String codeChallenge;

    public OAuthClientDemoController(@Value("${oauth.client.id}") String clientId,
                                     @Value("${oauth.client.secret}") String clientSecret,
                                     @Value("${oauth.token-endpoint}") String tokenEndpoint) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenEndpoint = tokenEndpoint;
    }

    /**
     * Browse to http://localhost:8080 and click the "Start Auth Code Flow" button to execute the demo
     */
    @GetMapping("/")
    public String main(Model model) throws NoSuchAlgorithmException {
        codeChallenge = UUID.randomUUID().toString();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String hashedCodeChallenge = Base64URL.encode(digest.digest(codeChallenge.getBytes(StandardCharsets.US_ASCII))).toString();

        log.info("codeChallenge = " + codeChallenge);
        log.info("hashedCodeChallenge = " + hashedCodeChallenge);
        log.info("clientId = " + clientId);

        model.addAttribute("hashedCodeChallenge", hashedCodeChallenge);
        model.addAttribute("accessToken", "NONE");
        model.addAttribute("clientId", clientId);

        return "main";
    }

    @GetMapping("/callback")
    public Mono<String> callback(Model model, @RequestParam String code, @RequestParam String state) {
        WebClient webClient = WebClient.builder()
                .baseUrl(tokenEndpoint)
                .clientConnector(new ReactorClientHttpConnector(HttpClient.create().wiretap(true)))
                .filter(basicAuthentication(clientId, clientSecret))
                .filter(logRequest())
                .build();

        Mono<Map> response = webClient
                .post()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("grant_type", "authorization_code")
                        .queryParam("redirect_uri", "http://localhost:8080/callback")
                        .queryParam("code", code)
                        .queryParam("code_verifier", codeChallenge)
                        .build())
                .retrieve()
                .bodyToMono(Map.class)
                .onErrorMap(throwable -> {
                    String responseBodyAsString = ((WebClientResponseException) throwable).getResponseBodyAsString();
                    log.error(responseBodyAsString);
                    return throwable;
                });

        return response.flatMap(map -> {
            if (map.get("access_token") != null) {
                String accessToken = map.get("access_token").toString();
                model.addAttribute("accessToken", accessToken);
            }
            return Mono.just("main");
        });
    }

    private static ExchangeFilterFunction logRequest() {
        return ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
            log.info("Request: {} {}", clientRequest.method(), clientRequest.url());
            clientRequest.headers().forEach((name, values) -> values.forEach(value -> log.info("{}={}", name, value)));
            return Mono.just(clientRequest);
        });
    }
}
