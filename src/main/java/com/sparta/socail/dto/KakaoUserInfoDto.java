package com.sparta.socail.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class KakaoUserInfoDto {
    private Long id;
    private String username;
    private String nickName;

    public KakaoUserInfoDto(Long id, String nickName) {
        this.id = id;
        this.nickName = nickName;
    }

    public KakaoUserInfoDto(String nickName) {
        this.nickName = nickName;
    }
}
