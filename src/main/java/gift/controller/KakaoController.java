package gift.controller;

import gift.service.KakaoService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;

@RestController
@Tag(name = "Kakao Authentication System", description = "Operations related to Kakao authentication")
public class KakaoController {
    private static final Logger logger = LoggerFactory.getLogger(KakaoController.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String GRANT_TYPE = "authorization_code";

    private final KakaoService kakaoService;

    @Value("${kakao.client-id}")
    private String clientId;

    @Value("${kakao.redirect-uri}")
    private String redirectUri;

    @Value("${kakao.auth-base-url}")
    private String authBaseUrl;

    @Value("${kakao.scope}")
    private String scope;

    @Autowired
    public KakaoController(KakaoService kakaoService) {
        this.kakaoService = kakaoService;
    }

    @GetMapping("/login")
    @Operation(summary = "Redirect to Kakao login", description = "Redirects the user to Kakao login page", tags = { "Kakao Authentication System" })
    public void redirectKakaoLogin(HttpServletResponse response) throws IOException {
        String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
        String encodedScope = URLEncoder.encode(scope, StandardCharsets.UTF_8);
        String kakaoLoginUrl = authBaseUrl +
                "?response_type=code" +
                "&client_id=" + clientId +
                "&redirect_uri=" + encodedRedirectUri +
                "&scope=" + encodedScope;

        logger.debug("Redirecting to Kakao login URL: {}", kakaoLoginUrl);

        response.sendRedirect(kakaoLoginUrl);
    }

    @GetMapping("/callback")
    @Operation(summary = "Kakao login callback", description = "Handles the callback after Kakao login", tags = { "Kakao Authentication System" })
    public ResponseEntity<String> callback(
            @Parameter(description = "Authorization code from Kakao")
            @RequestParam(required = false) String code) {
        if (code == null || code.isEmpty()) {
            logger.warn("Authorization code is missing");
            logger.info("Received code: {}", code);
            return ResponseEntity.badRequest().body("Authorization code is missing");
        }

        logger.debug("Authorization code received: {}", code);

        String accessToken;
        try {
            accessToken = kakaoService.getAccessToken(code);
        } catch (Exception e) {
            logger.error("Failed to get access token", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to get access token");
        }
        // 액세스 토큰 로그
        logger.debug("Access token received: {}", accessToken);

        return ResponseEntity.ok(accessToken);
    }

    @GetMapping("/member")
    @Operation(summary = "Get Kakao member information", description = "Fetches the Kakao member information using the authorization token", tags = { "Kakao Authentication System" })
    public ResponseEntity<String> getMember(
            @Parameter(description = "Authorization token", required = true)
            @RequestHeader(value = AUTHORIZATION_HEADER) String authorizationHeader) {
        String accessToken = authorizationHeader.replace(BEARER_PREFIX, "");

        logger.debug("Fetching member info with access token: {}", accessToken);

        return ResponseEntity.ok(kakaoService.getMember(accessToken).toString());
    }
}
