package com.sparta.socail.service;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparta.socail.repository.UserRepository;
import com.sparta.socail.security.JwtProperties;
import com.sparta.socail.security.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import com.sparta.socail.model.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class GoogleLoginService {

    @Value("${google.client-id}")
    String googleClientId;

    @Value("${google.client-secret}")
    String googleClientSecret;

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    // 구글 로그인
    public void googleLogin(String code, HttpServletResponse response) throws JsonProcessingException {

        // 인가코드로 엑세스토큰 가져오기
        String accessToken = getAccessToken(code);

        // 엑세스토큰으로 유저정보 가져오기
        JsonNode googleUserInfo = getGoogleUserInfo(accessToken);

        // 유저확인 & 회원가입
        User foundUser = getUser(googleUserInfo);

        // 시큐리티 강제 로그인
        UserDetailsImpl userDetails = securityLogin(foundUser);

        // jwt 토큰 발급
        jwtToken(response, userDetails);
    }

    // 인가코드로 엑세스토큰 가져오기
    private String getAccessToken(String code) throws JsonProcessingException {

        // 헤더에 Content-type 지정
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // 바디에 필요한 정보 담기
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id" , googleClientId);
        body.add("client_secret", googleClientSecret);
        body.add("code", code);
        body.add("redirect_uri", "http://localhost:8080/login/oauth2/code");
        body.add("grant_type", "authorization_code");

        // POST 요청 보내기
        HttpEntity<MultiValueMap<String, String>> googleToken = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(
                "https://oauth2.googleapis.com/token",
                HttpMethod.POST, googleToken,
                String.class
        );

        // response에서 엑세스토큰 가져오기
        String responseBody = response.getBody();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode responseToken = objectMapper.readTree(responseBody);
        String accessToken = responseToken.get("access_token").asText();
        return accessToken;
    }

    // 엑세스토큰으로 유저정보 가져오기
    private JsonNode getGoogleUserInfo(String accessToken) throws JsonProcessingException {

        // 헤더에 엑세스토큰 담기, Content-type 지정
        HttpHeaders headers = new HttpHeaders();
        headers.add(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + accessToken);
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        // POST 요청 보내기
        HttpEntity<MultiValueMap<String, String>> googleUser = new HttpEntity<>(headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(
                "https://openidconnect.googleapis.com/v1/userinfo",
                HttpMethod.POST, googleUser,
                String.class
        );

        // response에서 유저정보 가져오기
        String responseBody = response.getBody();
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode googleUserInfo = objectMapper.readTree(responseBody);
        return googleUserInfo;
    }

    // 유저확인 & 회원가입
    private User getUser(JsonNode googleUserInfo) {

        // 유저정보 작성
        String providerId = googleUserInfo.get("sub").asText();
        String providerEmail = googleUserInfo.get("email").asText();
        String provider = "google";
        String username = provider + "_" + providerId;
        String nickName = googleUserInfo.get("name").asText();
        Optional<User> nickNameCheck = userRepository.findByNickName(nickName);
        if (nickNameCheck.isPresent()) {
            String tempNickName = nickName;
            int i = 1;
            while (true){
                nickName = tempNickName + "_" + i;
                Optional<User> nickNameCheck2 = userRepository.findByNickName(nickName);
                if (!nickNameCheck2.isPresent()) {
                    break;
                }
                i++;
            }
        }
        String password = passwordEncoder.encode(UUID.randomUUID().toString());
        String profileImgUrl = "https://makecake.s3.ap-northeast-2.amazonaws.com/PROFILE/ef771589-abc6-4ddd-951c-73cc2420aa2fKakaoTalk_20220329_214148108.png";
//        UserRoleEnum role = UserRoleEnum.USER;

        // DB에서 username으로 가져오기 없으면 회원가입
        User findUser = userRepository.findByUsername(username).orElse(null);
        if (findUser == null) {
            findUser = User.builder()
                    .username(username)
                    .nickName(nickName)
                    .password(password)
//                    .profileImgUrl(profileImgUrl)
//                    .profileImgName(null)
//                    .role(role)
//                    .provider(provider)
//                    .providerId(providerId)
//                    .providerEmail(providerEmail)
                    .build();
            userRepository.save(findUser);
        }
        return findUser;
    }

    // 시큐리티 강제 로그인
    private UserDetailsImpl securityLogin(User findUser) {

        // userDetails 생성
        UserDetailsImpl userDetails = new UserDetailsImpl(findUser);
        log.info("google 로그인 완료 : " + userDetails.getUser().getUsername());
        // UsernamePasswordAuthenticationToken 발급
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        // 강제로 시큐리티 세션에 접근하여 authentication 객체를 저장
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return userDetails;
    }

    // jwt 토큰 발급
    private void jwtToken(HttpServletResponse response, UserDetailsImpl userDetails) {

        String jwtToken = JWT.create()
                // 토큰이름
                .withSubject("JwtToken : " + userDetails.getUser().getUsername())
                // 유효시간
                .withClaim("expireDate", new Date(System.currentTimeMillis() + JwtProperties.tokenValidTime))
                // username
                .withClaim("username", userDetails.getUser().getUsername())
                // HMAC256 복호화
                .sign(Algorithm.HMAC256(JwtProperties.secretKey));
        log.info("jwtToken : " + jwtToken);
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
    }
}