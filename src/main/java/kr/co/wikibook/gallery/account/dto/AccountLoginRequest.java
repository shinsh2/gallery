package kr.co.wikibook.gallery.account.dto;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class AccountLoginRequest {

    private String username;
    private String password;
}