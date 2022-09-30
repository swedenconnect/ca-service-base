package se.swedenconnect.ca.service.base.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import se.swedenconnect.ca.service.base.configuration.EmbeddedLogo;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventEnum;
import se.swedenconnect.ca.service.base.configuration.audit.AuditEventFactory;
import se.swedenconnect.ca.service.base.configuration.service.HtmlServiceInfo;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Error controller providing basic error page in case of service errors
 */
@Controller
public class ErrorController implements ApplicationEventPublisherAware {

    private static final String HTTP_ERROR_PAGE = "http-error";
    private static final String ERROR_MESSAGE = "message";
    private static final String ERROR_CODE = "errorCode";

    private final HtmlServiceInfo htmlServiceInfo;

    @Value("${ca-service.config.bootstrap-css}") String bootstrapCss;

    private ApplicationEventPublisher applicationEventPublisher;
    private final Map<String, EmbeddedLogo> logoMap;

    /**
     * Controller constructor
     *
     * @param logoMap logo map holding optional logotype data
     * @param htmlServiceInfo configured HTML service information
     */
    @Autowired
    public ErrorController(Map<String, EmbeddedLogo> logoMap, HtmlServiceInfo htmlServiceInfo) {
        this.logoMap = logoMap;
        this.htmlServiceInfo = htmlServiceInfo;
    }

    /**
     * HTTP 400 error handling
     *
     * @return redirect to bad request page
     */
    @RequestMapping("/400-redirect")
    public String errorRedirect400(){
        return "redirect:/bad-request";
    }

    /**
     * HTTP 404 error handling
     *
     * @return redirect to not found page
     */
    @RequestMapping("/404-redirect")
    public String errorRedirect404(){
        return "redirect:/not-found";
    }

    /**
     * HTTP 500 error handling
     *
     * @return redirect to internal error page
     */
    @RequestMapping("/500-redirect")
    public String errorRedirect500(){
        return "redirect:/internal-error";
    }

    /**
     * Not found error page
     *
     * @param model Spring model
     * @return error page
     */
    @RequestMapping("/not-found")
    public String get404Error(Model model) {
        model.addAttribute(ERROR_MESSAGE, "Requested service or page is not available");
        model.addAttribute(ERROR_CODE, "404");
        model.addAttribute("logoMap", logoMap);
        model.addAttribute("bootstrapCss", bootstrapCss);
        model.addAttribute("htmlInfo", htmlServiceInfo);
        return HTTP_ERROR_PAGE;
    }

    /**
     * Bad request error page
     *
     * @param model Spring model
     * @param request Http servlet request
     * @return error page
     */
    @RequestMapping("/bad-request")
    public String get400Error(Model model, HttpServletRequest request) {
        model.addAttribute(ERROR_MESSAGE, "Illegal Request for service");
        model.addAttribute(ERROR_CODE, "400");
        model.addAttribute("logoMap", logoMap);
        model.addAttribute("bootstrapCss", bootstrapCss);
        model.addAttribute("htmlInfo", htmlServiceInfo);
        return HTTP_ERROR_PAGE;
    }

    /**
     * Internal error page
     *
     * @param model Spring model
     * @return error page
     */
    @RequestMapping("/internal-error")
    public String get500Error(Model model) {
        applicationEventPublisher.publishEvent(new AuditApplicationEvent(AuditEventFactory.DEFAULT_AUDIT_PRINCIPAL, AuditEventEnum.internalError.getEventName()));
        model.addAttribute(ERROR_MESSAGE, "The request generated an internal error");
        model.addAttribute(ERROR_CODE, "500");
        model.addAttribute("logoMap", logoMap);
        model.addAttribute("bootstrapCss", bootstrapCss);
        model.addAttribute("htmlInfo", htmlServiceInfo);
        return HTTP_ERROR_PAGE;
    }

    /** {@inheritDoc} */
    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }
}
