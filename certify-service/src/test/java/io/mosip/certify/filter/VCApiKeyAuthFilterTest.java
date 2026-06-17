package io.mosip.certify.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VCApiKeyAuthFilterTest {

    @InjectMocks
    private VCApiKeyAuthFilter filter;

    @Mock
    private FilterChain filterChain;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private static final String SERVLET_PATH = "/v1/certify";
    private static final String VALID_API_KEY = "test-api-key";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        ReflectionTestUtils.setField(filter, "servletPath", SERVLET_PATH);
        ReflectionTestUtils.setField(filter, "apiKeysConfig", VALID_API_KEY + ",other-key");
        SecurityContextHolder.clearContext();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/v1/certify/vc-api/credentials/issue", "/v1/certify/vc-api/status"})
    void shouldFilterForVcApiUrls(String url) {
        request.setRequestURI(url);
        assertFalse(filter.shouldNotFilter(request));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/v1/certify/issuance/credential", "/v1/certify/oauth/token", "/health"})
    void shouldNotFilterForNonVcApiUrls(String url) {
        request.setRequestURI(url);
        assertTrue(filter.shouldNotFilter(request));
    }

    @Test
    void whenValidApiKey_shouldAuthenticateAndContinueChain() throws ServletException, IOException {
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");
        request.addHeader(VCApiKeyAuthFilter.API_KEY_HEADER, VALID_API_KEY);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertEquals(200, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void whenMissingApiKey_shouldReturnUnauthorized() throws ServletException, IOException {
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals(401, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void whenInvalidApiKey_shouldReturnUnauthorized() throws ServletException, IOException {
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");
        request.addHeader(VCApiKeyAuthFilter.API_KEY_HEADER, "wrong-key");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain, never()).doFilter(request, response);
        assertEquals(401, response.getStatus());
    }

    @Test
    void whenApiKeyHasSurroundingWhitespace_shouldAcceptTrimmedKey() throws ServletException, IOException {
        ReflectionTestUtils.setField(filter, "apiKeysConfig", " " + VALID_API_KEY + " ");
        request.setRequestURI(SERVLET_PATH + "/vc-api/credentials/issue");
        request.addHeader(VCApiKeyAuthFilter.API_KEY_HEADER, VALID_API_KEY);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertEquals(200, response.getStatus());
    }
}
