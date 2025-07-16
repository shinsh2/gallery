package kr.co.wikibook.gallery.account.dto;

import lombok.Getter;

@Getter
public class AccountLoginRequest {

    private String username;
    private String password;
}