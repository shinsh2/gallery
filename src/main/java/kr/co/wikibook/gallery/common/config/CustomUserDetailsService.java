package kr.co.wikibook.gallery.common.config;

import java.util.Collections;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import kr.co.wikibook.gallery.member.entity.Member;
import kr.co.wikibook.gallery.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. userRepository로부터 loginId로 유저정보를 받아온다.
		log.info("loadUserByUsername : {}", username);
		// 로그인 아이디로 회원을 조회
		// Optional<Member> byLoginId = memberRepository.findByLoginId(username);
    	Member member = memberRepository.findByLoginId(username)
                .orElseThrow(() -> new UsernameNotFoundException("not found loginId : " + username));
    	log.debug(member.toString());
//        // 2.user를 dto로 변환시켜준다.
//        UserDto userDto = UserDto.fromEntity(byLoginId);

        // 3. 사용자 정보를 기반으로 SecurityUserDetailsDto 객체를 생성한다.
        return new CustomUserDetails(
        		member,
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

//	@Override
//	public UserDetails updatePassword(UserDetails user, String newPassword) {
//        // 1. userRepository로부터 loginId로 유저정보를 받아온다.
//    	Member member = memberRepository.findByLoginId(user.getUsername())
//                .orElseThrow(() -> new UsernameNotFoundException("not found loginId : " + user.getUsername()));
//
////        // 2.user를 dto로 변환시켜준다.
////        UserDto userDto = UserDto.fromEntity(byLoginId);
//
//        // 3. 사용자 정보를 기반으로 SecurityUserDetailsDto 객체를 생성한다.
//        return new CustomUserDetails(
//        		member,
//                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
//        );
//	}

}