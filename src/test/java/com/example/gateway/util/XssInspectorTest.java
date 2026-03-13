package com.example.gateway.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class XssInspectorTest {

    private XssInspector xssInspector;

    @BeforeEach
    void setUp() {
        xssInspector = new XssInspector(new ObjectMapper());
    }

    @Test
    void shouldRejectJsonPayloadWithScriptTag() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/files")
                .contentType(MediaType.APPLICATION_JSON)
                .build();

        byte[] body = """
                {"title":"<script>alert('xss')</script>"}
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(xssInspector.detectViolation(request, body))
                .contains("XSS payload detected in request body.title");
    }

    @Test
    void shouldRejectMultipartJsonPartWithoutInspectingFileContent() {
        String boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        String multipartBody =
                "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
                "Content-Disposition: form-data; name=\"metadata\"\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "{\"description\":\"<img src=x onerror=alert(1)>\"}\r\n" +
                "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"doc.pdf\"\r\n" +
                "Content-Type: application/pdf\r\n" +
                "\r\n" +
                "%PDF-1.4 fake\r\n" +
                "------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n";

        MockServerHttpRequest request = MockServerHttpRequest.post("/api/files/upload")
                .contentType(MediaType.parseMediaType("multipart/form-data; boundary=" + boundary))
                .build();

        assertThat(xssInspector.detectViolation(request, multipartBody.getBytes(StandardCharsets.ISO_8859_1)))
                .contains("XSS payload detected in multipart json part.description");
    }

    @Test
    void shouldAllowMultipartFileWhenOnlyFileContentLooksSuspicious() {
        String boundary = "----Boundary";
        String multipartBody =
                "------Boundary\r\n" +
                "Content-Disposition: form-data; name=\"metadata\"\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "{\"description\":\"safe value\"}\r\n" +
                "------Boundary\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"note.txt\"\r\n" +
                "Content-Type: text/plain\r\n" +
                "\r\n" +
                "<script>this should be ignored because it is the uploaded file</script>\r\n" +
                "------Boundary--\r\n";

        MockServerHttpRequest request = MockServerHttpRequest.post("/api/files/upload")
                .contentType(MediaType.parseMediaType("multipart/form-data; boundary=" + boundary))
                .build();

        assertThat(xssInspector.detectViolation(request, multipartBody.getBytes(StandardCharsets.ISO_8859_1)))
                .isEmpty();
    }

    @Test
    void shouldRejectMaliciousQueryParameter() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/files?search=%3Cscript%3Ealert(1)%3C/script%3E")
                .build();

        assertThat(xssInspector.detectViolation(request, new byte[0]))
                .contains("XSS payload detected in query parameter: search");
    }

    @Test
    void shouldRejectAnchorTagInJsonPayload() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/files")
                .contentType(MediaType.APPLICATION_JSON)
                .build();

        byte[] body = """
                {"content":"<a href='https://example.com'>click</a>"}
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(xssInspector.detectViolation(request, body))
                .contains("XSS payload detected in request body.content");
    }

    @Test
    void shouldRejectEncodedJavascriptPayload() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/files")
                .contentType(MediaType.APPLICATION_JSON)
                .build();

        byte[] body = """
                {"content":"%253Csvg%2520onload%253Dalert(1)%253E"}
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(xssInspector.detectViolation(request, body))
                .contains("XSS payload detected in request body.content");
    }

    @Test
    void shouldRejectTextHtmlLikePayloadInTextBody() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/files")
                .contentType(MediaType.TEXT_PLAIN)
                .build();

        byte[] body = "<img src=x onerror=alert(1)>".getBytes(StandardCharsets.UTF_8);

        assertThat(xssInspector.detectViolation(request, body))
                .contains("XSS payload detected in request body");
    }

    @Test
    void shouldAllowHarmlessAngleBracketText() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/files")
                .contentType(MediaType.APPLICATION_JSON)
                .build();

        byte[] body = """
                {"content":"<burak>"}
                """.getBytes(StandardCharsets.UTF_8);

        assertThat(xssInspector.detectViolation(request, body))
                .isEmpty();
    }

    @Test
    void shouldRejectJsonMultipartPartEvenWhenBrowserSendsBlobFilename() {
        String boundary = "----WebKitFormBoundaryKB04XikZhPdKKApO";
        String multipartBody =
                "------WebKitFormBoundaryKB04XikZhPdKKApO\r\n" +
                "Content-Disposition: form-data; name=\"request\"; filename=\"blob\"\r\n" +
                "Content-Type: application/json\r\n" +
                "\r\n" +
                "{\"documentName\":\"<a href=\\\"javascript:alert(1)\\\">click</a>\",\"documentTypeId\":\"8dfc8ffe-f6db-4045-b91d-7bc1d0b20085\",\"decisionDate\":\"2026-03-13\",\"directorate\":\"YONETIM\",\"explanation\":\"safe\"}\r\n" +
                "------WebKitFormBoundaryKB04XikZhPdKKApO\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"test.pdf\"\r\n" +
                "Content-Type: application/pdf\r\n" +
                "\r\n" +
                "%PDF-1.4 fake\r\n" +
                "------WebKitFormBoundaryKB04XikZhPdKKApO--\r\n";

        MockServerHttpRequest request = MockServerHttpRequest.post("/api/v1/documents")
                .contentType(MediaType.parseMediaType("multipart/form-data; boundary=" + boundary))
                .build();

        assertThat(xssInspector.detectViolation(request, multipartBody.getBytes(StandardCharsets.ISO_8859_1)))
                .contains("XSS payload detected in multipart json part.documentName");
    }
}
