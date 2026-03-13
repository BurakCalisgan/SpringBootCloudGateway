package com.example.gateway.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class XssInspector {

    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String MULTIPART_JSON_PART = "multipart json part";
    private static final String MULTIPART_FIELD_MESSAGE = "XSS payload detected in multipart field";
    private static final String BODY_INSPECTION_ERROR = "Request body could not be inspected safely";

    private static final Pattern[] XSS_PATTERNS = {
            Pattern.compile("<\\s*/?\\s*[a-z][a-z0-9:-]*\\b[^>]*>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<\\s*script", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript\\s*:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("vbscript\\s*:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("data\\s*:\\s*text/html", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("expression\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("srcdoc\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("xmlns", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<\\s*(iframe|object|embed|svg|img|body|input|video|audio)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<\\s*(a|link|style|meta|form|base|math)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("document\\s*\\.\\s*(cookie|write)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("window\\s*\\.\\s*location", Pattern.CASE_INSENSITIVE),
            Pattern.compile("alert\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("prompt\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("confirm\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("eval\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("innerhtml\\s*=", Pattern.CASE_INSENSITIVE)
    };

    private final ObjectMapper objectMapper;

    public Optional<String> detectViolation(ServerHttpRequest request, byte[] bodyBytes) {
        Optional<String> queryViolation = inspectQueryParams(request.getQueryParams());
        if (queryViolation.isPresent()) {
            return queryViolation;
        }

        MediaType contentType = request.getHeaders().getContentType();
        if (bodyBytes == null || bodyBytes.length == 0 || contentType == null) {
            return Optional.empty();
        }

        try {
            return inspectBody(contentType, bodyBytes);
        } catch (IOException | InvalidMediaTypeException exception) {
            return Optional.of(BODY_INSPECTION_ERROR);
        }
    }

    private Optional<String> inspectQueryParams(MultiValueMap<String, String> queryParams) {
        for (String key : queryParams.keySet()) {
            for (String value : queryParams.getOrDefault(key, java.util.List.of())) {
                if (containsXss(value)) {
                    return Optional.of("XSS payload detected in query parameter: " + key);
                }
            }
        }
        return Optional.empty();
    }

    private Optional<String> inspectBody(MediaType contentType, byte[] bodyBytes) throws IOException {
        if (isJson(contentType)) {
            return inspectJson(bodyBytes, "request body");
        }

        if (MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(contentType)) {
            return inspectFormUrlEncoded(bodyBytes);
        }

        if (MediaType.MULTIPART_FORM_DATA.isCompatibleWith(contentType)) {
            return inspectMultipart(bodyBytes, contentType);
        }

        if (!isTextual(contentType)) {
            return Optional.empty();
        }

        return inspectTextBody(bodyBytes, "XSS payload detected in request body");
    }

    private Optional<String> inspectJson(byte[] bodyBytes, String source) throws IOException {
        JsonNode root = objectMapper.readTree(bodyBytes);
        return inspectJsonNode(root, source);
    }

    private Optional<String> inspectJsonNode(JsonNode node, String path) {
        if (node == null) {
            return Optional.empty();
        }

        if (node.isTextual() && containsXss(node.asText())) {
            return Optional.of("XSS payload detected in " + path);
        }

        if (node.isObject()) {
            var fields = node.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                Optional<String> violation = inspectJsonNode(entry.getValue(), path + "." + entry.getKey());
                if (violation.isPresent()) {
                    return violation;
                }
            }
        }

        if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                Optional<String> violation = inspectJsonNode(node.get(i), path + "[" + i + "]");
                if (violation.isPresent()) {
                    return violation;
                }
            }
        }

        return Optional.empty();
    }

    private Optional<String> inspectFormUrlEncoded(byte[] bodyBytes) {
        String rawBody = new String(bodyBytes, StandardCharsets.UTF_8);
        if (rawBody.isBlank()) {
            return Optional.empty();
        }

        for (String pair : rawBody.split("&")) {
            String[] keyValue = pair.split("=", 2);
            String key = decodeValue(keyValue[0]);
            String value = keyValue.length > 1 ? decodeValue(keyValue[1]) : "";

            if (containsXss(value)) {
                return Optional.of("XSS payload detected in form field: " + key);
            }
        }

        return Optional.empty();
    }

    private Optional<String> inspectMultipart(byte[] bodyBytes, MediaType contentType) throws IOException {
        String boundary = contentType.getParameter("boundary");
        if (boundary == null || boundary.isBlank()) {
            return Optional.of("Multipart request boundary is missing");
        }

        String body = new String(bodyBytes, StandardCharsets.ISO_8859_1);
        String[] rawParts = body.split(Pattern.quote("--" + boundary));

        for (String rawPart : rawParts) {
            Optional<String> violation = inspectMultipartPart(rawPart);
            if (violation.isPresent()) {
                return violation;
            }
        }

        return Optional.empty();
    }

    private Optional<String> inspectMultipartPart(String rawPart) throws IOException {
        if (!shouldInspectMultipartPart(rawPart)) {
            return Optional.empty();
        }

        String normalizedPart = trimMultipartPart(rawPart);
        int headerEndIndex = normalizedPart.indexOf("\r\n\r\n");
        if (headerEndIndex < 0) {
            return Optional.empty();
        }

        String headers = normalizedPart.substring(0, headerEndIndex);
        MediaType partContentType = resolvePartContentType(headers);
        if (shouldSkipMultipartPart(headers, partContentType)) {
            return Optional.empty();
        }

        String partBody = normalizedPart.substring(headerEndIndex + 4);
        byte[] partBodyBytes = trimTrailingCrlf(partBody).getBytes(StandardCharsets.ISO_8859_1);

        if (isJson(partContentType)) {
            return inspectJson(partBodyBytes, MULTIPART_JSON_PART);
        }

        return inspectTextBody(partBodyBytes, MULTIPART_FIELD_MESSAGE);
    }

    private boolean shouldInspectMultipartPart(String rawPart) {
        return rawPart != null
                && !rawPart.isBlank()
                && !rawPart.equals("--")
                && !rawPart.equals("--\r\n");
    }

    private boolean isFilePart(String headers) {
        return headers.toLowerCase(Locale.ROOT).contains("filename=");
    }

    private boolean shouldSkipMultipartPart(String headers, MediaType partContentType) {
        return isFilePart(headers) && !isJson(partContentType);
    }

    private MediaType resolvePartContentType(String headers) {
        String partContentTypeValue = extractContentTypeHeader(headers);
        if (partContentTypeValue == null) {
            return MediaType.TEXT_PLAIN;
        }
        return MediaType.parseMediaType(partContentTypeValue);
    }

    private Optional<String> inspectTextBody(byte[] bodyBytes, String violationMessage) {
        String body = new String(bodyBytes, StandardCharsets.UTF_8);
        return containsXss(body) ? Optional.of(violationMessage) : Optional.empty();
    }

    private String extractContentTypeHeader(String headers) {
        for (String line : headers.split("\r\n")) {
            if (line.regionMatches(true, 0, CONTENT_TYPE_HEADER + ":", 0, CONTENT_TYPE_HEADER.length() + 1)) {
                return line.substring(CONTENT_TYPE_HEADER.length() + 1).trim();
            }
        }
        return null;
    }

    private String trimMultipartPart(String rawPart) {
        String normalized = rawPart;
        if (normalized.startsWith("\r\n")) {
            normalized = normalized.substring(2);
        }
        if (normalized.endsWith("--")) {
            normalized = normalized.substring(0, normalized.length() - 2);
        }
        return normalized;
    }

    private String trimTrailingCrlf(String value) {
        if (value.endsWith("\r\n")) {
            return value.substring(0, value.length() - 2);
        }
        return value;
    }

    private boolean isJson(MediaType mediaType) {
        String subtype = mediaType.getSubtype();
        return MediaType.APPLICATION_JSON.isCompatibleWith(mediaType)
                || subtype.toLowerCase(Locale.ROOT).endsWith("+json");
    }

    private boolean isTextual(MediaType mediaType) {
        return "text".equalsIgnoreCase(mediaType.getType())
                || MediaType.APPLICATION_XML.isCompatibleWith(mediaType)
                || MediaType.TEXT_XML.isCompatibleWith(mediaType);
    }

    private boolean containsXss(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }

        String normalized = normalize(value);
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(normalized).find()) {
                return true;
            }
        }
        return false;
    }

    private String normalize(String value) {
        String normalized = value;
        for (int i = 0; i < 2; i++) {
            normalized = decodeValue(normalized);
        }
        normalized = normalized
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&#x27;", "'")
                .replace("&#39;", "'")
                .replace("&amp;", "&")
                .replace("&#x3c;", "<")
                .replace("&#60;", "<")
                .replace("&#x3e;", ">")
                .replace("&#62;", ">")
                .replace("\\u003c", "<")
                .replace("\\u003e", ">");
        return normalized.toLowerCase(Locale.ROOT);
    }

    private String decodeValue(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException exception) {
            return value;
        }
    }
}
