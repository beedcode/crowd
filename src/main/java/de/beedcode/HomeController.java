package de.beedcode;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@Controller
public class HomeController {

    @RequestMapping(value = "hello", method = RequestMethod.GET)
    public ModelAndView hello(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();

        ModelAndView mav = new ModelAndView("hello");
        mav.addObject("name", principal.getName());

        return mav;
    }
}
