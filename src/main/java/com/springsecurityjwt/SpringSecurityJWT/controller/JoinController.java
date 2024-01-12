package com.springsecurityjwt.SpringSecurityJWT.controller;

import com.springsecurityjwt.SpringSecurityJWT.Dto.JoinDto;
import com.springsecurityjwt.SpringSecurityJWT.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String join(JoinDto joinDto) {

        Boolean joined = joinService.joinProcess(joinDto);

        return joined ? "ok" : "error";
    }
}
