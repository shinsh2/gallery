package kr.co.wikibook.gallery.account.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AccountJoinRequest {

    private String name;
    private String loginId;
    private String loginPw;
}